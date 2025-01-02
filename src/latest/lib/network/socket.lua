local socket = {}
local socketMethods = {}

local function findModem()
    if _G.mitp.modem then return _G.mitp.modem end

    local modems = { peripheral.find("modem") }
    for _, modem in ipairs(modems) do
        if modem.isWireless() then
            _G.mitp.modem = modem
            return modem
        end
    end

    printError("No wireless modem was detected, please attach one.")
    error()
end

function socket.new(port, replyIp, replyPort)
    local newSocket = {
        modem = findModem(),
        source = {
            ip = os.getComputerID(),
            port = port
        },
        destination = {
            ip = replyIp,
            port = replyPort
        },
        seq = nil,
        ack = nil,
        buffer = {},
        connected = false,
        secret = nil
    }

    newSocket.modem.open(port)

    setmetatable(newSocket, { __index = socketMethods } )
    return newSocket
end

function socketMethods:sendPacket(payload)
    self.modem.transmit(self.destination.port, self.source.port, payload)
end

function socketMethods:receivePacket(mss)
    if type(mss) ~= "number" and type(mss) ~= "nil" then return end

    local timerID
    if mss then timerID = os.startTimer(mss) end

    local message

    local function waitForTimer()
        while true do
            local _, id = os.pullEvent("timer")
            if id == timerID then
                return
            end
        end
    end

    local waitForMessage = function () _, _, _, _, message = os.pullEvent("modem_message") end
    parallel.waitForAny(waitForMessage, waitForTimer)

    if message then
        if timerID then os.cancelTimer(timerID) end
        return message
    else
        return false
    end
end

function socketMethods:closeSocket()
    self.modem.close(self.source.port)
    self.seq = nil
    self.ack = nil
    self.buffer = {}
    self.connected = false
    self.secret = nil
end

return {newSocket = function (port, replyIp, replyPort)
    return socket.new(port, replyIp, replyPort)
end
}
