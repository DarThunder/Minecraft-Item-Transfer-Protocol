--Funciones a agregar:
--parseRequest()
--buildResponse()
--ParseMessageBody()
--verifyCredentials()
--HandleError()
--sendErrorResponse()
--encryptData()
--checkAccessPermissions()
--emitEvent()

local MITP = {}
MITP.version = "0.6"

--Inits
MITP.IP = nil
MITP.modem = nil
MITP.sessions = {}
MITP.ephemeralPort = nil
MITP.standardPort = nil
MITP.sequenceNumber = nil
MITP.status = {["pending"] = true, ["complete"] = true, ["error"] = true}

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
    MITP.IP = os.getComputerID()
    MITP.modem = validModem()
    MITP.standardPort = 80
    MITP.modem.open(MITP.standardPort)
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

        valid, errMessage, logType= validateField(MITP.status[buildedMessage.headers.status], "Invalid Status")
        if not valid then return valid, errMessage, logType end

        valid, errMessage, logType = validateField(MITP.sessions[buildedMessage.headers.destination], "Failed Resolve IP")
        if not valid then return valid, errMessage, logType end

    elseif buildedMessage.flag then
        local flags = {["SYN"] = true, ["SYN-ACK"] = true, ["ACK"] = true, ["FIN"] = true}

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
    if MITP.modem.isOpen(port) then
        return true, "Port already openned", "Warn"
    end
    return false
end

function MITP.validateRecipent(recipent)
    return MITP.IP == recipent
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

function MITP.checksum(data)
    local checksum = 0

    if type(data) == "string" then
        checksum = checksum + sumString(data)
    elseif type(data) == "number" then
        checksum = checksum + data
    elseif type(data) == "table" then
        checksum = checksum + sumTable(data)
    else
        MITP.displayError("Data type not supported. try string or table")
    end

    return string.format("%02x", checksum % 256)
end


--funciones de manipluación de data
function MITP.buildTCPMessage(destinationIP, flag, sequenceNumber, acknowledgmentNumber)
    local TCPmessage = {
        source = MITP.IP,
        destination = destinationIP,
        flag = flag,
        sequence_number = sequenceNumber,
        ack = acknowledgmentNumber
    }
    return TCPmessage
end

function MITP.buildMITPMessage(destinationIP, method, status, body, contentType)
    local MITPmessage = {
        headers = {
            mitp_version = MITP.version,
            content_type = contentType or "item/json",
            source = MITP.IP,
            destination = destinationIP,
            timestamp = os.date("%c"),
            status = status,
            method = method
        },
        body = body
    }
    MITPmessage.headers.checksum = MITP.checksum(MITPmessage)
    return MITPmessage
end

function MITP.serializeMessage(message)
    return textutils.serializeJSON(message)
end

function MITP.parseMessage(message)
    return textutils.unserializeJSON(message)
end


--funciones de sesion
function MITP.createSession(ip, port, sequenceNumber)
    if MITP.validateSession(ip) then
        MITP.log("Session already exists", "WAR")
    end
    MITP.sessions[ip] = {port = port, sequenceNumber = sequenceNumber}
    MITP.log("Session with IP " .. ip .. " created succesful", "INFO")
end

function MITP.destroySession(ip)
    local valid, errMessage, logType = MITP.validateSession(ip)
    if not valid then MITP.log(errMessage, logType) return end

    MITP.sessions[ip] = nil
    MITP.log("Session with IP " .. ip .. " destroyed succesful", "INFO")
end


--funciones de conexión
function MITP.openEphemeralPort()
    MITP.ephemeralPort = math.random(49152, 65535)
    MITP.modem.open(MITP.ephemeralPort)
end

function MITP.closeEphemeralPort()
    MITP.modem.close(MITP.ephemeralPort)
end

function MITP.send(buildedMessage, channel, replyChannel)
    local parsedMessage = MITP.serializeMessage(buildedMessage)
    MITP.modem.transmit(channel, replyChannel, parsedMessage)
end

function MITP.listenConnection()
    local event, side, channel, replyChannel, message, distance = os.pullEvent()
    return event, side, channel, replyChannel, message, distance
end

function MITP.connectionTimeOut(buildedMessage, sendPort, replyPort)
    for attemps = 1,3 do
        MITP.send(buildedMessage, sendPort, replyPort)
        os.startTimer(attemps)
        local event, side, channel, replyChannel, message = MITP.listenConnection()
        if event == "modem_message" then
            return event, side, channel, replyChannel, message
        end
        MITP.log("Retrying connection to IP after failure", "WARN")
    end
    MITP.log("Connection time out", "ERROR")
    return false
end

function MITP.sendClose(ip, sendChannel, replyChannel)
    local closePacket = MITP.buildTCPMessage(ip, "FIN", MITP.sequenceNumber, 0)
    local event, _, _, _, ackMessage = MITP.connectionTimeOut(closePacket, sendChannel, replyChannel)
    if not event then MITP.log("Connection time out", "ERROR") return end
    if event ~= "modem_message" then return end

    local parsedMessage = MITP.parseMessage(ackMessage)
    if parsedMessage.flag == "ACK" and parsedMessage.ack == MITP.sequenceNumber + 1 then
        MITP.destroySession(parsedMessage.source)
        MITP.log("Connection closed successfully from this side.", "INFO")
    else
        MITP.log("Error closing connection.", "ERROR")
    end
end

function MITP.handleClose(parsedMessage, sendChannel, replyChannel)
    local acknowledgmentNumber = parsedMessage.sequence_number + 1
    local ackPacket = MITP.buildTCPMessage(parsedMessage.source, "ACK", MITP.sequenceNumber, acknowledgmentNumber)
    MITP.send(ackPacket, sendChannel, replyChannel)
    MITP.destroySession(parsedMessage.source)
    MITP.log("Connection closed successfully from remote side.", "INFO")
end

return MITP

