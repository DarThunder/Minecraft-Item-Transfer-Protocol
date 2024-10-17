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
--getSupportedVersion()

local MITP = {}
MITP.version = "0.5"

--Inits
MITP.IP = os.getComputerID()
MITP.modem = peripheral.wrap("front")
MITP.sessions = {}
MITP.ephemeralPort = nil
MITP.standardPort = 80
MITP.sequenceNumber = nil
MITP.modem.open(MITP.standardPort)
MITP.status = {["pending"] = true, ["complete"] = true, ["error"] = true}


--funciones de registro/deputación
function MITP.log(log, logType)
    local date = os.date("%Y-%m-%d")
    local file = "logs/log_" .. date .. ".log"
    local logFile = fs.open(file, "a")

    local hour = textutils.formatTime(os.time("local"))
    local errMsg = "[" .. hour .. "] [" .. (logType or "INFO") .. "]: " .. log .. "\n"
    logFile.write(errMsg)
    logFile.close()
end

function MITP.displayError(err)
    error(err)
end


--funciones genericas
--WIP

--funciones de validacion
local function validateType(buildedMessage)
    if type(buildedMessage) ~= "table" then
        return false, "Expecting table, got " .. type(buildedMessage), "ERROR"
    end
    return true
end

local function validatePresence(buildedMessage)
    if not buildedMessage.headers then
        return false, "headers are required", "ERROR"
    end
    return true
end

local function validateStatus(buildedMessage)
    if buildedMessage.headers.status then
        if not (buildedMessage.headers.status and buildedMessage.headers.content_type and buildedMessage.headers.destination and buildedMessage.headers.checksum) then
            return false, "Incomplete headers", "ERROR"
        end

        if not MITP.status[buildedMessage.headers.status] then
            return false, "Invalid Status", "ERROR"
        end

        if not MITP.sessions[buildedMessage.headers.destination] then
            return false, "Failed Resolve IP", "ERROR"
        end
    end
    return true
end

function MITP.validateInput(buildedMessage)
    local valid, errMessage, logType
    valid, errMessage, logType = validateType(buildedMessage)
    if not valid then return valid, errMessage, logType end

    valid, errMessage, logType = validatePresence(buildedMessage)
    if not valid then return valid, errMessage, logType end

    valid, errMessage, logType = validateStatus(buildedMessage)
    if not valid then return valid, errMessage, logType end

    return true, "Validation succesful", "INFO"
end

function MITP.validateSession(ip)
    if not MITP.sessions[ip] then
        return false, "Failed to Resolve IP", "ERROR"
    end
    return true
end

local function validatePort(port)
    if MITP.modem.isOpen(port) then
        return true, "Port already openned", "Warn"
    end
    return false
end


--funciones de integridad de data
function MITP.checksum(data)
    local checksum = 0

    if type(data) == "string" then
        for i = 1, #data do
            checksum = checksum + string.byte(data, i)
        end
    elseif type(data) == "table" then
        for _, value in pairs(data) do
            if type(value) == "string" then
                for i = 1, #value do
                    checksum = checksum + string.byte(value, i)
                end
            elseif type(value) == "number" then
                checksum = checksum + value
            end
        end
    else
        MITP.displayError("Tipo de dato no soportado. Usa un string o una tabla.")
    end

    return checksum % 256
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

function MITP.buildMITPMessage(destinationIP, status, body, contentType)
    local MITPmessage = {
        headers = {
            mitp_version = MITP.version,
            content_type = contentType or "item/json",
            source = MITP.IP,
            destination = destinationIP,
            timestamp = os.date("%c"),
            status = status,
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
    local valid, errMessage, logType = MITP.validateSession(ip)
    if not valid then MITP.log(errMessage, logType) return end

    MITP.sessions[ip] = {port = port, sequenceNumber = sequenceNumber}
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
    return false
end

function MITP.sendClose(ip, sendChannel, replyChannel)
    local closePacket = MITP.buildTCPMessage(ip, "FIN", MITP.sequenceNumber)
    local event, _, _, _, ackMessage = MITP.connectionTimeOut(closePacket, sendChannel, replyChannel)
    if not event then MITP.log("Connection time out", "ERROR") return end
    if event ~= "modem_message" then return end

    local parsedMessage = MITP.parseMessage(ackMessage)
    if parsedMessage.flag == "ACK" and parsedMessage.ack == MITP.sequenceNumber + 1 then
        MITP.destroySession(parsedMessage.source)
        MITP.log("Connection closed successfully from this side.")
    else
        MITP.log("Error closing connection.", "ERROR")
    end
end

function MITP.handleClose(buildedMessage, sendChannel, replyChannel)
    local parsedMessage = MITP.parseMessage(buildedMessage)

    if parsedMessage.flag == "FIN" then
        local acknowledgmentNumber = parsedMessage.sequence_number + 1
        local ackPacket = MITP.buildTCPMessage(parsedMessage.source, "ACK", acknowledgmentNumber)
        MITP.send(ackPacket, sendChannel, replyChannel)
        MITP.log("Connection closed successfully from remote side.")
        MITP.destroySession(parsedMessage.source)
    end
end

return MITP
