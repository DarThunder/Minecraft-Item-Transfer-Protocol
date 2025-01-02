require("lib/var/server")
local AES = require("lib/cipher/encryptLib")
local huffman = require("lib/compress/huffman")

local server = {}
local serverMethods = {}

local function shallowCopy(orig, metaSocket)
    local copy = {}
    for k, v in pairs(orig) do
        copy[k] = v
    end
    setmetatable(copy, metaSocket)
    return copy
end

local function findFlag(flag)
    for value, t in ipairs(_G.mitp.flags) do
        if t.name == flag then
            return value
        end
    end
end

function server.new(newServer)
    for methodName, method in pairs(serverMethods) do
        newServer[methodName] = method
    end
end

function serverMethods:on(flag, action)
    if not flag or not action then printError("Flag and action paramaters requiered") error() end
    if type(flag) ~= "string" then printError("Flag must be a string") error() end
    if type(action) ~= "function" then printError("Action must be a function") error() end

    local value = findFlag(flag)
    if not value then
        if not self.addFlag(flag, action) then printError("An error occurred while adding the flag " .. flag .. " please try again") error() end
    else
        if not self.addAction(value, action) then printError("An error occurred while adding the action to flag" .. flag .. " please try again") error() end
    end
end

function serverMethods:autoRecv()
    local incomingPackets = {}
    local processPackets = {}
    local soldierQueue = {}
    local customQueue = {}

    local function auto()
        while true do
            local _, packet = os.pullEvent("packet_receive")
            if self.sockets[packet.headers.source.ip] or not packet.data then
                table.insert(incomingPackets, packet)
                os.queueEvent("packet_handler")
            end
        end
    end

    local function handler()
        while true do
            os.pullEvent("packet_handler")
            local packet = table.remove(incomingPackets, 1)
            local socket = self.sockets[packet.headers.source.ip] or shallowCopy(self.sockets.listener, getmetatable(self.sockets.listener))

            table.insert(processPackets, {socket = socket, packet = packet})
            os.queueEvent("packet_process")
        end
    end

    local function processPacketData(processPacket)
        if processPacket.packet.data then
            processPacket.packet.data.data = AES.decryptAES(processPacket.packet.data.data, processPacket.socket.secret)
            processPacket.packet.data.data = huffman.decompress(processPacket.packet.data.data, processPacket.packet.data.associative_table, processPacket.packet.data.dataType)
        end
    end

    local function executePacketAction(processPacket)
        local selfServer = self.sockets[processPacket.packet.headers.source.ip] and nil or self
        local packetFunc = _G.mitp.flags[processPacket.packet.headers.control_block.flag].action
        if type(packetFunc) == "function" then
            local connection = { socket = processPacket.socket }
            setmetatable(connection, getmetatable(self))
            packetFunc(connection, processPacket.packet, selfServer)
        end
    end

    local function process()
        while true do
            os.pullEvent("packet_process")

            local processPacket = table.remove(processPackets, 1)
            processPacketData(processPacket)

            if processPacket then
                if processPacket.packet.headers.control_block.flag == 0x02 then
                    processPacket.socket.destination.ip = processPacket.packet.headers.source.ip
                    processPacket.socket.destination.port = processPacket.packet.headers.source.port
                end
                if processPacket.packet.headers.control_block.flag <= 0x03 then
                    table.insert(soldierQueue, processPacket)
                    os.queueEvent("soldier")
                else
                    table.insert(customQueue, processPacket)
                    os.queueEvent("custom")
                end
            end
        end
    end

    local function soldier()
        while true do
            os.pullEvent("soldier")
            executePacketAction(table.remove(soldierQueue, 1))
        end
    end

    local function customSoldier()
        while true do
            os.pullEvent("custom")

            local tasks = {}
            for _, packet in ipairs(customQueue) do
                table.insert(tasks, function()
                    executePacketAction(packet)
                end)
            end

            customQueue = {}
            if #tasks > 0 then
                parallel.waitForAll(table.unpack(tasks))
            end
        end
    end

    parallel.waitForAll(
        function() self.receive({ socket = self.sockets.listener, sendFlag = self.sendFlag, generateSeq = self.generateSeq }, nil, true) end,
        auto,
        handler,
        process,
        soldier,
        customSoldier
    )
end

return {
  instanceServer = function (newSever)
      server.new(newSever)
  end
}
