_G.mitp = _G.mitp or {}

local TCP = require("/protocol/lib/network/Tcp")
local socket = require("/protocol/lib/network/socket")

local MITP = {}
local Version = "1.0"

function MITP:client(ip, replyPort)
    local client = require("/protocol/lib/network/client")
    local newClient = {}

    local port = math.random(2^15 * 1.5, 2^16 - 1)
    newClient.socket = socket.newSocket(port, ip, replyPort)

    setmetatable(newClient, { __index = TCP })
    client.instanceClient(newClient)
    return newClient
end

function MITP:server(port)
    local server = require("/protocol/lib/network/server")
    local newServer = {}

    newServer.sockets = {listener = socket.newSocket(port, nil, nil)}

    setmetatable(newServer, { __index = TCP })
    server.instanceServer(newServer)
    return newServer
end

return {
  Client = {
      new = function (serverIp, serverPort)
          return MITP:client(serverIp, serverPort)
      end
  },
  Server = {
      new = function (port)
          return MITP:server(port)
      end
  }
}
