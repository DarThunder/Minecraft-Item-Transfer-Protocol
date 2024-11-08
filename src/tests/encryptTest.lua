package.path = package.path .. ";../latest/lib/?.lua"
local AES = require("encryptLib")

local salt = AES.generateSalt(32)
local secret = AES.sha256(tostring(math.random(2^0, 2^32)))

local word = ""
local encryptWord = AES.encryptAES(word, secret, salt)
local decryptWord = AES.decryptAES(encryptWord, secret, salt)

print("Palabra encriptada: " .. encryptWord)
print("Palabra desencriptada: " .. decryptWord)
