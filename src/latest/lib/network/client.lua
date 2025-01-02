local AES = require("/protocol/lib/cipher/encryptLib")
local huffman = require("/protocol/lib/compress/huffman")

local client = {}
local clientMethods = {}

local function sendSYN(currentClient, publicKey)
    currentClient:sendFlag(0x02, publicKey)
end

local function configSocket(socket, secret)
    socket.connected = true
    socket.secret = secret .. AES.sha256(secret)
end

local function configClient(currentClient)
    for name, func in pairs(clientMethods) do
        currentClient[name] = func
    end
end

function client:open()
    local secrets = {}
    AES.generateSecrets(secrets)
    if not secrets then printError("Failed to create secrets") error() end

    sendSYN(self, { publicKey = secrets.public_key, p = secrets.p, g = secrets.g })
    local syn_ack = self:receive(3)
    if not syn_ack then printError("Error trying to establish connection with ip " .. self.socket.destination.ip .. " address") error() end
    if not syn_ack.DH then printError("Failed to exchange secrets") error() end

    local secret = AES.modExp(syn_ack.DH.public_key, secrets.private_key, secrets.p)
    configSocket(self.socket, tostring(secret))
    configClient(self)
end

local function findFlag(flag)
    if type(flag) ~= "string" then printError("Flag must be a string") error() end
    for flagValue, flagParam in ipairs(_G.mitp.flags) do
        if flagParam.name == flag then
            return flagValue
        end
    end
end

function clientMethods:transmit(payload, flag)
    local flagValue
    if flag then
        flagValue = findFlag(flag)
        if not flagValue then
            if not self.addFlag(flag) then printError("An error occurred while adding the flag " .. flag .. " please try again") error() end
        end
    end

    self:send(payload, flagValue)
end

function clientMethods:recv()
    local packet = self:receive(1)
    if packet and packet.data then
        packet.data.data = AES.decryptAES(packet.data.data, self.socket.secret)
        packet.data.data = huffman.decompress(packet.data.data, packet.data.associative_table, packet.data.dataType)
    end
    return packet
end

return { instanceClient = function (currentClient)
    client.open(currentClient)
end}
