local AES = require("lib/cipher/encryptLib")
local dataUtils = require("lib/utils/dataUtils")

local valid = {}

local function validField(condition, errorMessage)
    if not condition then
        return false, errorMessage, "ERROR"
    end
    return true
end

local function validateType(_, packet)
    return validField(type(packet) == "table", "invalid packet type")
end

local function validParameters(_, packet)
    return validField(packet.headers, "insufficient parameters")
end

local function validChecksum(_, packet)
    local packetChecksum = packet.headers.checksum
    packet.headers.checksum = nil

    local checksum = AES.sha256(dataUtils.serializeJSON(packet))
    return validField(checksum == packetChecksum, "Checksum mismatch")
end

local function validHeader(_, packet)
    if type(packet.headers) ~= "table" then
        return false, "Header should be a table", "ERROR"
    end

    local requireMetadata = {"source", "destination", "sequence_number", "control_block"}

    for _, metadata in pairs(requireMetadata) do
        if not packet.headers[metadata] then
            return false, "Parameter " .. metadata .. " is required", "ERROR"
        end
    end
    return true
end

local function validIp(ip)
    return validField(type(ip) == "number", "Failed to resolve IP")
end

local function validPort(port)
    return validField(type(port) == "number" and port <= 2^16 - 1, "Invalid port")
end

--Work in progress (no really)
--[[local function validSeq(seq, ack)
    return validField(ack == seq, "Invalid ack")
end]]

local function validFlag(flag)
    return validField(_G.mitp.flags[flag], "Invalid flag")
end

local function validHeaderInfo(socket, packet)
    local status, errMessage, logType
    status, errMessage, logType =  validIp(packet.headers.source.ip)
    if not status then return status, errMessage, logType end

    status, errMessage, logType = validIp(packet.headers.destination.ip)
    if not status then return status, errMessage, logType end

    status, errMessage, logType = validPort(packet.headers.source.port)
    if not status then return status, errMessage, logType end

    status, errMessage, logType = validPort(packet.headers.destination.port)
    if not status then return status, errMessage, logType end

    --Work in progress (no, seriously, really not)
    --[[status, errMessage, logType = validSeq(socket.seq, packet.headers.ack)
    if not status then return status, errMessage, logType end]]

    status, errMessage, logType = validFlag(packet.headers.control_block.flag)
    if not status then return status, errMessage, logType end

    return true
end

function valid.validateInput(socket, packet)
    local validators = {validateType, validParameters, validChecksum, validHeader, validHeaderInfo}

    for _, validator in ipairs(validators) do
        local status, errMessage, logType = validator(socket, packet)
        if not status then return status, errMessage, logType end
    end

    return true
end

return valid
