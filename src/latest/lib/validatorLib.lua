local VALIDATOR = {}
local AES = require("lib/encryptLib")
local validStatus = {["pending"] = true, ["complete"] = true, ["error"] = true}
local flags = {["SYN"] = true, ["SYN_ACK"] = true, ["ACK"] = true, ["FIN"] = true, ["RECV"] = true, ["NRECV"] = true}

local function validateField(condition, errorMessage)
    if not condition then
        return false, errorMessage, "ERROR"
    end
    return true
end

local function validateType(buildedMessage, _, _)
    local valid, errMessage, logType = validateField(type(buildedMessage) == "table", "Expecting table, got " .. type(buildedMessage))
    if not valid then return valid, errMessage, logType end
    return true
end

local function validatePresence(buildedMessage, _, _)
    local valid, errMessage, logType = validateField((buildedMessage.headers or buildedMessage.flag), "Headers are required")
    if not valid then return valid, errMessage, logType end
    return true
end

local function validateChecksum(buildedMessage, _, _)
    _ = textutils.serializeJSON(buildedMessage)
    local localChecksum = AES.sha256(_)
    local valid, errMessage, logType
    if buildedMessage.flag then
        valid, errMessage, logType = validateField(localChecksum == buildedMessage.checksum)
    else
       valid, errMessage, logType = validateField(localChecksum == buildedMessage.headers.checksum)
    end
    if not valid then return valid, errMessage, logType end
    return true
end

local function validateHeaders(buildedMessage, sessions, ip)
    local requiredHeaders = {"status", "content_type", "destination", "checksum"}
    local valid, errMessage, logType
    for _, header in ipairs(requiredHeaders) do
        valid, errMessage, logType = validateField(buildedMessage.headers[header], header .. " is required")
        if not valid then return valid, errMessage, logType end
    end

    valid, errMessage, logType = validateField(validStatus[buildedMessage.headers.status], "Invalid Status")
    if not valid then return valid, errMessage, logType end

    valid, errMessage, logType = validateField(sessions[buildedMessage.headers.source], "Failed Resolve IP")
    if not valid then return valid, errMessage, logType end

    valid = validateField(buildedMessage.headers.destination == ip, "")
    if not valid then return valid, nil, nil end
end

local function validateFlags(buildedMessage, _, ip)
    local requiredTcpParams = {"source", "destination", "flag", "sequence_number", "ack"}
    local valid, errMessage, logType
    for _, param in ipairs(requiredTcpParams) do
        valid, errMessage, logType = validateField(buildedMessage[param], param .. " is required")
        if not valid then return valid, errMessage, logType end
    end

    valid, errMessage, logType = validateField(flags[buildedMessage.flag], "Unknown flag")
    if not valid then return valid, errMessage, logType end

    valid = validateField(buildedMessage.destination == ip, "")
    if not valid then return valid, nil, nil end
end

local function validateForm(buildedMessage, sessions, ip)

    if buildedMessage.headers then
        validateHeaders(buildedMessage, sessions, ip)
    elseif buildedMessage.flag then
        validateFlags(buildedMessage, sessions, ip)
    end

    return true
end

function VALIDATOR.validateInput(buildedMessage, sessions, ip)
    local validators = {validateType, validatePresence, validateForm, validateChecksum}

    for _, validator in ipairs(validators) do
        local valid, errMessage, logType = validator(buildedMessage, sessions, ip)
        if not valid then return valid, errMessage, logType end
    end

    return true, "Validation successful", "INFO"
end

return VALIDATOR
