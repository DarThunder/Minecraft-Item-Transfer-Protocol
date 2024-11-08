--Funciones a agregar:
--verifyCredentials()
--sendErrorResponse()
--checkAccessPermissions()
local AES = require("lib/encryptLib")
local VALIDATORS = require("lib/validatorLib")

local HANDLERS = {}
local MITP = {}
MITP.client = {}
MITP.version = "0.8"
MITP.ephemeralPort = nil
MITP.standardPort = nil
MITP.sessions = {}


--Inits
local IP = nil
local modem = nil
local sequenceNumber = nil
local messages = {}
local events = {}
local lastAccion = {}
local secrets = {}

local function findModem()
    local modems = {peripheral.find("modem")}
    for i = 1, #modems do
        if modems[i].isWireless() then
            return modems[i]
        end
    end
    return nil
end

function MITP.init()
    IP = os.getComputerID()
    modem = findModem()
    MITP.standardPort = 80
    modem.open(MITP.standardPort)
end

function MITP.depose()
    if #MITP.sessions > 0 then
        for ip, _ in pairs(MITP.sessions) do
            MITP.close(ip)
        end
    end
    for i = 2^0, 2^16-1 do
        modem.close(i)
    end
end


--funciones de registro/depuración
function MITP.log(log, logType)
    if log and logType then
        local date = os.date("%Y-%m-%d")
        local file = "logs/log_" .. date .. ".log"
        local logFile = fs.open(file, "a")

        local hour = textutils.formatTime(os.time("local"))
        local errMsg = "[" .. hour .. "] [" .. (logType) .. "]: " .. log .. "\n"
        logFile.write(errMsg)
        logFile.close()
    end
end


--funciones genericas
local function await(ms)
    ms = ms or 3
    os.startTimer(ms)
    while true do
        local event, _, channel, replyChannel, message = os.pullEvent()
        if event == "modem_message" then
            local valid = HANDLERS.proccessRequest(message, channel, replyChannel)
            if valid and (valid.flag == "SYN_ACK" or valid.flag == "ACK") then
                HANDLERS.handlerTCPFlags(valid, channel, replyChannel)
                return
            end
        elseif event == "timer" then
            MITP.log("Connection time out", "ERROR")
            return
        end
    end
end

local function shrieker(eventType, ipSession, message)
    ipSession = MITP.sessions[ipSession]
    local callbacks = events[eventType]
    if callbacks then
        for _, callback in ipairs(callbacks) do
            local success = pcall(function()
                callback(ipSession, message)
            end)
            if success then
                lastAccion[1] = {action = callback, param1 = ipSession, param2 = message}
            end
        end
    end
end

function MITP.on(eventType, callback)
    if type(callback) ~= "function" then
        MITP.log("Expecting function, got" .. type(callback), "ERROR")
        return
    end
    if not events[eventType] then
        events[eventType] = {}
    end
    table.insert(events[eventType], callback)
end


--funciones de manipulación de data
local function buildTCPMessage(destinationIP, flag, sequence_number, acknowledgmentNumber, public_key)
    local TCPmessage = {
        source = IP,
        destination = destinationIP,
        flag = flag,
        sequence_number = sequence_number,
        ack = acknowledgmentNumber,
        public_key = public_key,
    }
    TCPmessage.checksum = AES.sha256(MITP.serializeMessage(TCPmessage))
    return TCPmessage
end

function MITP.buildMessage(destinationIP, method, status, body, contentType)
    local MITPmessage = {
        headers = {
            mitp_version = MITP.version,
            content_type = contentType or "item/json",
            source = IP,
            destination = destinationIP,
            timestamp = os.date("%c"),
            status = status,
            method = method
        },
        body = body
    }
    MITPmessage.headers.checksum = AES.sha256(MITP.serializeMessage(MITPmessage))
    return MITPmessage
end

function MITP.serializeMessage(message)
    return textutils.serializeJSON(message)
end

function MITP.parseMessage(message)
    return textutils.unserializeJSON(message)
end

function MITP.parseMessageBody(message)
    return MITP.parseMessage(message).body
end


--Funciones de consistencia de data
local function sendRECV(ip, channel, replyChannel)
    local recvPacket = buildTCPMessage(ip, "RECV", sequenceNumber, 0)
    MITP.send(recvPacket, channel, replyChannel)
end
local function sendNRECV(ip, channel, replyChannel)
    local nrecvPacket = buildTCPMessage(ip, "NRECV", sequenceNumber, 0)
    MITP.send(nrecvPacket, channel, replyChannel)
end


--funciones de sesion
local function createSession(ip, port, replyPort, sharedKey, salt)
    if MITP.sessions[ip] then
        MITP.log("Session already exists", "WARN")
        return
    end
   MITP.sessions[ip] = {port = port, reply_port = replyPort, shared_key = sharedKey, salt = salt}
    MITP.log("Session with IP " .. ip .. " created succesful", "INFO")
    shrieker("connect", ip, nil)
end

local function destroySession(ip)
    if not MITP.sessions[ip] then
        MITP.log("Failed to resolve session", "ERROR")
        return
    end

    MITP.sessions[ip] = nil
    MITP.log("Session with IP " .. ip .. " destroyed succesful", "INFO")
    shrieker("disconnect", ip, nil)
end

local function getSession(port)
    for key, value in pairs(MITP.sessions) do
        if value.reply_port == port then
            return key
        end
    end
    return nil
end


--funciones de conexión
function MITP.openEphemeralPort()
    MITP.ephemeralPort = math.random(2^15 * 1.5, 2^16 - 1)
    modem.open(MITP.ephemeralPort)
end

function MITP.closeEphemeralPort()
    modem.close(MITP.ephemeralPort)
end

function MITP.send(buildedMessage, channel, replyChannel)
    local parsedMessage = MITP.serializeMessage(buildedMessage)
    if buildedMessage.headers then
        local sharedKey = MITP.sessions[buildedMessage.headers.destination].shared_key
        local salt = MITP.sessions[buildedMessage.headers.destination].salt
        parsedMessage = AES.encryptAES(parsedMessage, sharedKey, salt)
    end
    modem.transmit(channel, replyChannel, parsedMessage)
end

function MITP.sendErrorResponse(destinationIP, errorMessage)
    local errorResponse = MITP.buildMessage(destinationIP, "ERROR", "error", errorMessage, "application/json")
    MITP.send(errorResponse, MITP.standardPort)
    MITP.log("Error response sent to " .. destinationIP .. ": " .. errorMessage, "WARN")
end

local function listenConnection(filter)
    if not filter then filter = nil end
    local event, side, channel, replyChannel, message, distance = os.pullEvent(filter)
    return event, side, channel, replyChannel, message, distance
end

function MITP.open(destinationIP)
    sequenceNumber = math.random(2^0, 2^32)
    AES.generateSecrets(secrets)
    MITP.openEphemeralPort()
    local synPacket = buildTCPMessage(destinationIP, "SYN", sequenceNumber, 0, secrets.public_key)
    MITP.send(synPacket, MITP.standardPort, MITP.ephemeralPort)
    MITP.log("SYN sent, waiting for SYN-ACK...", "INFO")
    await()
end

local function openResponse(parsedMessage, sendChannel, replyChannel)
    sequenceNumber = math.random(2^0, 2^32)
    AES.generateSecrets(secrets)
    secrets.shared_key = AES.modExp(parsedMessage.public_key, secrets.private_key, secrets.p)
    secrets.shared_key = tostring(secrets.shared_key)
    local synAckPacket = buildTCPMessage(parsedMessage.source, "SYN_ACK", sequenceNumber, parsedMessage.sequence_number + 1, secrets.public_key)
    MITP.send(synAckPacket, sendChannel, replyChannel)
    MITP.log("SYN-ACK sent, awaiting final ACK...", "INFO")
end

function MITP.close(ip)
    local sendChannel = MITP.sessions[ip].port
    local replyChannel = MITP.sessions[ip].reply_port
    local closePacket = buildTCPMessage(ip, "FIN", sequenceNumber, 0)
    MITP.send(closePacket, sendChannel, replyChannel)
    MITP.log("FIN sent, waiting for ACK...", "INFO")
    await()
end

local function closeResponse(parsedMessage, sendChannel, replyChannel)
    if not parsedMessage.sequence_number then
        MITP.log("Invalid sequence number in FIN packet", "ERROR")
        return
    end

    local acknowledgmentNumber = parsedMessage.sequence_number + 1
    local ackPacket = buildTCPMessage(parsedMessage.source, "ACK", sequenceNumber, acknowledgmentNumber)

    MITP.send(ackPacket, sendChannel, replyChannel)
    destroySession(parsedMessage.source)
    MITP.log("Connection closed successfully from remote side.", "INFO")
end

local function synAckResponse(parsedMessage, channel, replyChannel)
    secrets.shared_key = AES.modExp(parsedMessage.public_key, secrets.private_key, secrets.p)
    secrets.shared_key = tostring(secrets.shared_key)
    secrets.salt = AES.sha256(secrets.shared_key)

    local ackPacket= buildTCPMessage(parsedMessage.source, "ACK", sequenceNumber, parsedMessage.sequence_number + 1)
    MITP.send(ackPacket, MITP.standardPort, MITP.ephemeralPort)
    createSession(parsedMessage.source, channel, replyChannel, secrets.shared_key, secrets.salt)
    MITP.log("Received SYN-ACK, connection established", "INFO")
end

local function ackResponse(parsedMessage, channel, replyChannel)
    if parsedMessage.ack == sequenceNumber + 1 then
        if MITP.sessions[parsedMessage.source] then
            destroySession(parsedMessage.source)
        else
            secrets.salt = AES.sha256(secrets.shared_key)
            createSession(parsedMessage.source, channel, replyChannel, secrets.shared_key, secrets.salt)
            MITP.log("Connection handshake complete with ACK", "INFO")
        end
    else
        MITP.log("ACK sequence mismatch", "ERROR")
    end
end


--Procesadores
function HANDLERS.proccessRequest(message, channel, replyChannel)
    local parsedMessage = MITP.parseMessage(message)

    if not parsedMessage then
        local ip = getSession(replyChannel)
        local secret = MITP.sessions[ip].shared_key
        local salt = MITP.sessions[ip]. salt
        message = AES.decryptAES(message, secret, salt)

        if not message then
            MITP.log("Failed to parse message", "ERROR")
            return nil, nil, nil
        else
            parsedMessage = MITP.parseMessage(message)

        end
    end

    local ip = parsedMessage.headers and parsedMessage.headers.source or parsedMessage.source
    local valid, errMessage, logType = VALIDATORS.validateInput(parsedMessage, MITP.sessions, IP)
    if valid then
        if (parsedMessage.flag and parsedMessage.flag ~= "RECV") or parsedMessage.headers then
            sendRECV(ip, channel, replyChannel)
        end
        return parsedMessage, channel, replyChannel
    else
        MITP.log(errMessage, logType)
        sendNRECV(ip, channel, replyChannel)
        return nil, nil, nil
    end
end


--handlers
function HANDLERS.handlerTCPFlags(packetMessage, channel, replyChannel)
    local tcpHandlers = {
        SYN = function()
            MITP.log("Synchronize request", "INFO")
            openResponse(packetMessage, channel, replyChannel)
        end,
        SYN_ACK = function ()
            MITP.log("Synchronize response", "INFO")
            synAckResponse(packetMessage, channel, replyChannel)
        end,
        ACK = function ()
            MITP.log("ACK response", "INFO")
            ackResponse(packetMessage, channel, replyChannel)
        end,
        FIN = function()
            MITP.log("Terminate connection request", "INFO")
            closeResponse(packetMessage, channel, replyChannel)
        end,
        RECV = function ()
            --MITP.log("Succesful receive packet", "INFO")
        end,
        NRECV = function ()
            MITP.log("Packet received with errors, resending", "WARN")
            lastAccion[1].action(lastAccion[1].param1, lastAccion[1].param2)
        end,
        }

    local handler = tcpHandlers[packetMessage.flag]
    if handler then
        handler()
    else
        MITP.log("Unknown TCP flag '" .. packetMessage.flag .. "'", "WARN")
        sendNRECV(packetMessage.source, channel, replyChannel)
    end
end

function HANDLERS.handlerMITPMessages(packetMessage)
    local eventType = packetMessage.headers.method
    shrieker(eventType, packetMessage.headers.source, packetMessage)
end

local function handlerRequests()
    while true do
        local value = table.remove(messages)
        if value then
            if value.message.flag then
                HANDLERS.handlerTCPFlags(value.message, value.port, value.replyPort)
            elseif value.message.headers then
                HANDLERS.handlerMITPMessages(value.message)
            end
        end
        os.sleep(0.1)
    end
end


--Loops
function MITP.recv()
    local _, _, channel, replyChannel, message, _ = listenConnection("modem_message")
    return HANDLERS.proccessRequest(message, channel, replyChannel)
end

function MITP.autoRecv()
    local function receiveLoop()
        while IP do
            local parsedMessage, channel, replyChannel = MITP.recv()
            if parsedMessage then
                table.insert(messages, {message = parsedMessage, port = channel, replyPort = replyChannel})
            end
        end
    end

    parallel.waitForAny(receiveLoop, handlerRequests)
end

return MITP
