if not _G.mitp.flags then printError("'mitp.flags' global table not found. Please ensure it is initialized correctly.") error() end

local AES = require("lib/cipher/encryptLib")

_G.mitp.flags[0x01].action = function (conn)
    conn = nil
end

_G.mitp.flags[0x02].action = function (conn, packet, server)
    local privateKey = AES.generateSecretNumber(packet.DH.p)
    conn.socket.secret = AES.modExp(packet.DH.public_key, privateKey, packet.DH.p)
    conn:sendFlag(0x02, {publicKey = AES.modExp(packet.DH.g, privateKey, packet.DH.p)})

    server.sockets[packet.headers.source.ip] = conn.socket
end
