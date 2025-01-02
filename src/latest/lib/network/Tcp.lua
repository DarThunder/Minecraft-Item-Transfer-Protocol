local AES = require("lib/cipher/encryptLib")
local dataUtils = require("lib/utils/dataUtils")
local valid = require("lib/utils/validLib")

local TCP = {}
local MAX_SIZE = 128

function TCP:generateSeq()
    self.socket.seq = self.socket.seq and self.socket.seq + 1 or math.random(1, 10000)
    return self.socket.seq
end

function TCP.segmentData(data, mss)
    local segments = {}
    local i = 1
    while i <= #data do
        table.insert(segments, data:sub(i, i + mss - 1))
        i = i + mss
    end
    return segments
end

function TCP:sendFlag(flag, DH)
    if type(flag) ~= "number" or type(DH) ~= "table" then
        dataUtils.log("Invalid flag or data type", "ERROR")
        return
    end

    self:generateSeq()
    local packet = dataUtils.buildMessage(self.socket, {flag = flag, DH = DH, remain = 0})

    if packet then
        self.socket:sendPacket(packet)
    else
        dataUtils.log("Error building message", "ERROR")
    end
end

function TCP:send(data, flag)
    local server = self.socket.server

    local function waitForAck()
        local _, ack = os.pullEvent("ack")
        return ack
    end

    local function waitForTimer(timerID)
        while true do
            local _, id = os.pullEvent("timer")
            if id == timerID then
                return true
            end
        end
    end

    local packet = dataUtils.buildMessage(self.socket, {
        flag = flag or 0x04,
        remain = 0,
        data = data,
        secret = self.socket.secret
    })

    if not packet then
        dataUtils.log("Error building message", "ERROR")
        return
    end

    local segments = TCP.segmentData(packet.data.data, MAX_SIZE)
    local remain = #segments - 1
    local maxRetries = 3
    local timeout = 1

    for _, segment in ipairs(segments) do
        self:generateSeq()
        packet.headers.sequence_number = self.socket.seq
        packet.headers.remain = remain
        packet.data.data = segment

        packet.headers.checksum = nil
        packet.headers.checksum = AES.sha256(dataUtils.serializeJSON(packet))

        local retries = 0
        while retries <= maxRetries do
            self.socket:sendPacket(packet)

            local status = false
            if server then
                local timerID = os.startTimer(timeout)

                parallel.waitForAny(function()
                    local ack = waitForAck()
                    if ack then
                        os.cancelTimer(timerID)
                        status = true
                    end
                end, function()
                    waitForTimer(timerID)
                end)
            else
                local ack = self.socket:receivePacket(timeout)
                status = valid.validateInput(self.socket, ack)
            end
            if status then
                break
            end

            retries = retries + 1
            if retries > maxRetries then
                dataUtils.log("Failed to receive valid ACK after maximum retries", "ERROR")
                return
            end
        end

        remain = remain - 1
    end

    return true
end

function TCP:receive(mss, server)
    local segmentBuffer = {}

    local function handlerPacket(packet)
        if server then
            if packet.headers.control_block.flag == 0x02 then
                self.socket.destination.port = nil
                self.socket.destination.ip = nil
            end
            os.queueEvent("packet_receive", packet)
        else
            return packet
        end
    end

    while true do
        local packet = self.socket:receivePacket(mss)
        if not packet then return end

        local status, errMessage, logType = valid.validateInput(self.socket, packet)
        if not status then
            dataUtils.log(errMessage, logType)
            goto continue
        end

        if packet.data then
            if server then
                self.socket.destination.ip = packet.headers.source.ip
                self.socket.destination.port = packet.headers.source.port
            end

            self:sendFlag(0x03, {})

            local ip = packet.headers.source.ip
            segmentBuffer[ip] = segmentBuffer[ip] or {}
            table.insert(segmentBuffer[ip], packet.data.data)

            if packet.headers.remain == 0 then
                packet.data.data = table.concat(segmentBuffer[ip])
                segmentBuffer[ip] = nil

                packet = handlerPacket(packet)
                if packet then return packet end
            end
        else
            packet = handlerPacket(packet)
            if packet then return packet end
        end
        ::continue::
    end
end

function TCP:close()
    self:sendFlag(0x01, {})

    local response = self:receive(3)
    if response then
        dataUtils.log("Connection closed successfully.", "INFO")
        self.socket:closeSocket()
    else
        dataUtils.log("Failed to receive ACK for connection closure", "ERROR")
    end
end

function TCP.addFlag(flagType, action)
    if type(flagType) ~= "string" then dataUtils.log("Flag must be a string", "ERROR") return end
    if type(action) ~= "function" and type(action) ~= "nil" then dataUtils.log("Action must be a function or nil", "ERROR") return end

    local flagValue = #_G.mitp.flags + 1

    if _G.mitp.flags[flagValue] then dataUtils.log("Flag " .. flagValue .. " already exists.", "WARN") end

    _G.mitp.flags[flagValue] = {}
    _G.mitp.flags[flagValue].name = flagType
    _G.mitp.flags[flagValue].action = action
    dataUtils.log("Flag added successfully: " .. flagType, "INFO")

    return true
end

function TCP.addAction(flag, action)
    if type(flag) ~= "number" then dataUtils.log("Unknown flag value", "ERROR") return end
    if type(action) ~= "function" then dataUtils.log("Unknown action value", "ERROR") return end
    if not _G.mitp.flags[flag] then dataUtils.log("Unknown flag", "ERROR") return end

    _G.mitp.flags[flag].action = action
    dataUtils.log("Action added successfully to flag " .. flag, "INFO")

    return true
end

local function loadFlags()
    _G.mitp.flags = _G.mitp.flags or {
        [0x01] = {name = "FIN", action = nil},
        [0x02] = {name = "SYN", action = nil},
        [0x03] = {name = "ACK", action = nil},
        [0x04] = {name = "DATA", action = nil}
    }
end

loadFlags()

return TCP
