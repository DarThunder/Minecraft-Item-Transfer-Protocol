
--Funciones a agregar:
--verifyCredentials()
--sendErrorResponse()
--encryptData()
--checkAccessPermissions()

local MITP = {}
MITP.client = {}
MITP.version = "0.7"

--Inits
local IP = nil
local modem = nil
local sequenceNumber = nil
MITP.ephemeralPort = nil
MITP.standardPort = nil
MITP.sessions = {}
local validStatus = {["pending"] = true, ["complete"] = true, ["error"] = true}
local flags = {["SYN"] = true, ["SYN-ACK"] = true, ["ACK"] = true, ["FIN"] = true}
local messages = {}
local events = {}

local function validModem()
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
    modem = validModem()
    MITP.standardPort = 80
    modem.open(MITP.standardPort)
end

--funciones de registro/deputación
function MITP.log(log, logType)
    local date = os.date("%Y-%m-%d")
    local file = "logs/log_" .. date .. ".log"
    local logFile = fs.open(file, "a")

    local hour = textutils.formatTime(os.time("local"))
    local errMsg = "[" .. hour .. "] [" .. (logType) .. "]: " .. log .. "\n"
    logFile.write(errMsg)
    logFile.close()
end

function MITP.displayError(err)
    error(err)
end


--funciones genericas
local function await(ms)
    ms = ms or 5
    os.startTimer(ms)
    local event = os.pullEvent()
    local _ = event == "modem_message" and true or MITP.log("Connection time out", "ERROR")
    return _
end

local function shrieker(eventType, ipSession, message)
    ipSession = MITP.sessions[ipSession]
    local callbacks = events[eventType]
    if callbacks then
        for _, callback in ipairs(callbacks) do
            callback(ipSession, message)
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


--funciones de validacion
local function validateField(condition, errorMessage)
    if not condition then
        return false, errorMessage, "ERROR"
    end
    return true
end

local function validateType(buildedMessage)
    local valid, errMessage, logType = validateField(type(buildedMessage) == "table", "Expecting table, got " .. type(buildedMessage))
    if not valid then return valid, errMessage, logType end
    return true
end

local function validatePresence(buildedMessage)
    local valid, errMessage, logType = validateField((buildedMessage.headers or buildedMessage.flag), "Headers are required")
    if not valid then return valid, errMessage, logType end
    return true
end

local function validateFlags(buildedMessage)
    local valid, errMessage, logType
    if buildedMessage.headers then
        valid, errMessage, logType = validateField(buildedMessage.headers.status and buildedMessage.headers.content_type and buildedMessage.headers.destination and buildedMessage.headers.checksum, "Incomplete headers")
        if not valid then return valid, errMessage, logType end

        valid, errMessage, logType= validateField(validStatus[buildedMessage.headers.status], "Invalid Status")
        if not valid then return valid, errMessage, logType end

        valid, errMessage, logType = validateField(MITP.sessions[buildedMessage.headers.source], "Failed Resolve IP")
        if not valid then return valid, errMessage, logType end

    elseif buildedMessage.flag then
        valid, errMessage, logType = validateField((buildedMessage.source and buildedMessage.destination and buildedMessage.flag and buildedMessage.sequence_number and buildedMessage.ack), "Incomple TCP parameters")
        if not valid then return valid, errMessage, logType end

        valid, errMessage, logType = validateField(flags[buildedMessage.flag], "Unknown flag")
        if not valid then return valid, errMessage, logType end
    end
    return true
end

function MITP.validateInput(buildedMessage)
    local validators = {validateType, validatePresence, validateFlags}

    for _, validator in ipairs(validators) do
        local valid, errMessage, logType = validator(buildedMessage)
        if not valid then return valid, errMessage, logType end
    end

    return true, "Validation successful", "INFO"
end

function MITP.validateSession(ip)
    if not MITP.sessions[ip] then
        return false, "Failed to Resolve IP", "ERROR"
    end
    return true
end

function MITP.validatePort(port)
    if modem.isOpen(port) then
        return true, "Port already openned", "Warn"
    end
    return false
end

function MITP.validateRecipent(recipent)
    return IP == recipent
end


--funciones de integridad de data
local function sumString(str)
    local sum = 0
    for i = 1, #str do
        sum = sum + string.byte(str, i)
    end
    return sum
end

local function sumTable(t)
    local sum = 0
    for _, value in pairs(t) do
        if type(value) == "table" then
            sum = sum + sumTable(value)
        elseif type(value) == "string" then
            sum = sum + sumString(value)
        elseif type(value) == "number" then
            sum = sum + value
        end
    end
    return sum
end

local function checksum(data)
    local checksumTotal = 0

    if type(data) == "string" then
        checksumTotal = checksumTotal + sumString(data)
    elseif type(data) == "number" then
        checksumTotal = checksumTotal + data
    elseif type(data) == "table" then
        checksumTotal = checksumTotal + sumTable(data)
    else
        MITP.displayError("Data type not supported. try string or table")
    end

    return string.format("%02x", checksumTotal % 256)
end


--funciones de manipluación de data
local function buildTCPMessage(destinationIP, flag, sequence_number, acknowledgmentNumber)
    local TCPmessage = {
        source = IP,
        destination = destinationIP,
        flag = flag,
        sequence_number = sequence_number,
        ack = acknowledgmentNumber
    }
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
    MITPmessage.headers.checksum = checksum(MITPmessage)
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


--funciones de sesion
local function createSession(ip, port, sequence_number)
    if MITP.validateSession(ip) then
        MITP.log("Session already exists", "WARN")
    end
    MITP.sessions[ip] = {port = port, sequence_number = sequence_number}
    MITP.log("Session with IP " .. ip .. " created succesful", "INFO")
    shrieker("connect", ip, nil)
end

local function destroySession(ip)
    local valid, errMessage, logType = MITP.validateSession(ip)
    if not valid then MITP.log(errMessage, logType) return end

    MITP.sessions[ip] = nil
    MITP.log("Session with IP " .. ip .. " destroyed succesful", "INFO")
    shrieker("disconnect", ip, nil)
end


--funciones de conexión
function MITP.openEphemeralPort()
    MITP.ephemeralPort = math.random(2^15 * 3, 2^16 - 1)
    modem.open(MITP.ephemeralPort)
end

function MITP.closeEphemeralPort()
    modem.close(MITP.ephemeralPort)
end

function MITP.send(buildedMessage, channel, replyChannel)
    local parsedMessage = MITP.serializeMessage(buildedMessage)
    modem.transmit(channel, replyChannel, parsedMessage)
end

local function listenConnection(filter)
    if not filter then filter = nil end
    local event, side, channel, replyChannel, message, distance = os.pullEvent(filter)
    return event, side, channel, replyChannel, message, distance
end

function MITP.open(destinationIP)
    local synPacket = buildTCPMessage(destinationIP, "SYN", sequenceNumber, 0)
    MITP.send(synPacket, MITP.standardPort, MITP.ephemeralPort)
    MITP.log("SYN sent, waiting for SYN-ACK...", "INFO")
    await()
end

local function openResponse(parsedMessage, sendChannel, replyChannel)
    sequenceNumber = math.random(2^0, 2^32)
    local synAckPacket = buildTCPMessage(parsedMessage.source, "SYN-ACK", sequenceNumber, parsedMessage.sequence_number + 1)
    MITP.send(synAckPacket, sendChannel, replyChannel)
    MITP.log("SYN-ACK sent, awaiting final ACK...", "INFO")
    await()
end

function MITP.close(ip, replyChannel)
    local sendChannel = MITP.sessions[ip].port
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

    if MITP.send(ackPacket, sendChannel, replyChannel) then
        destroySession(parsedMessage.source)
        MITP.log("Connection closed successfully from remote side.", "INFO")
    else
        MITP.log("Failed to send ACK for FIN packet", "ERROR")
    end
end

local function synAckResponse(parsedMessage)
    sequenceNumber = math.random(2^0, 2^32)
    local ackPacket= buildTCPMessage(parsedMessage.source, "ACK", sequenceNumber, parsedMessage.sequence_number + 1)
    MITP.send(ackPacket, MITP.standardPort, MITP.ephemeralPort)
    createSession(parsedMessage.source, MITP.standardPort, parsedMessage.sequence_number)
    MITP.log("Received SYN-ACK, connection established", "INFO")
end

local function ackResponse(parsedMessage)
    if parsedMessage.ack == sequenceNumber + 1 then
        MITP.sequenceNumber = parsedMessage.ack
        MITP.log("Connection handshake complete with ACK", "INFO")
    else
        MITP.log("ACK sequence mismatch", "ERROR")
    end
end


--handlers
local function handlerTCPFlags(packetMessage, channel, replyChannel)
    local tcpHandlers = {
        SYN = function()
            MITP.log("Synchronize request", "INFO")
            openResponse(packetMessage, channel, replyChannel)
        end,
        SYN_ACK = function ()
            MITP.log("Synchronize response", "INFO")
            synAckResponse(packetMessage)
        end,
        ACK = function ()
            MITP.log("ACK response", "INFO")
            ackResponse(packetMessage)
        end,
        FIN = function()
            MITP.log("Terminate connection request", "INFO")
            closeResponse(packetMessage, channel, replyChannel)
        end,
        }

    local handler = tcpHandlers[packetMessage.flag]
    if handler then
        handler()
    else
        MITP.log("Unknown TCP flag '" .. packetMessage.flag .. "'", "WARN")
    end
end

local function handlerMITPMessages(packetMessage)
    local eventType = packetMessage.headers.method
    shrieker(eventType, packetMessage.headers.source, packetMessage)
end


local function handlerRequests()
    while true do
        local value = table.remove(messages)
        if value then
            if value.message.flag then
                handlerTCPFlags(value.message, value.sourceIP, value.replyIP)
            elseif value.message.headers then
                handlerMITPMessages(value.message)
            end
        end
        os.sleep(0.1)
    end
end


--Loops
function MITP.recv()
    local _, _, channel, replyChannel, message, _ = listenConnection("modem_message")
    local parsedMessage = MITP.parseMessage(message)
    if not parsedMessage then
        MITP.log("Failed to parse message", "ERROR")
        return nil, nil, nil
    end
    local valid, errMessage, logType = MITP.validateInput(parsedMessage)
    if valid then
        if parsedMessage.flag then
            valid = MITP.validateRecipent(parsedMessage.destination)
        elseif parsedMessage.headers then
            valid = MITP.validateRecipent(parsedMessage.headers.destination)
        else
            valid = false
        end
        --print(valid)
        if valid then return parsedMessage, channel, replyChannel end
    else
        MITP.log(errMessage, logType)
    end

    return nil, nil, nil
end

function MITP.autoRecv()
    local function receiveLoop()
        while true do
            local parsedMessage, channel, replyChannel = MITP.recv()
            if parsedMessage then
                table.insert(messages, {message = parsedMessage, port = channel, replyPort = replyChannel})
            end
            --os.sleep(0.1)
        end
    end

    parallel.waitForAny(receiveLoop, handlerRequests)
end

return MITP

--[[function MITP.handleError(err)
    MITP.log(err, "ERROR")
    MITP.closeEphemeralPort()
    sequenceNumber = nil
    MITP.displayError(err)
end]]
