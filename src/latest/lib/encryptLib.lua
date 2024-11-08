local bit = require("bit32")

local cipher = {}
math.randomseed(math.randomseed(os.time() + tonumber(tostring(os.clock()):reverse():sub(1, 5))))

local function generateRandomBits(n)
    local bits = {}

    bits[1] = 1
    bits[n] = 1

    for i = 2, n - 1 do
        bits[i] = math.random(0, 1)
    end

    local bitString = table.concat(bits)
    return tonumber(bitString, 2)
end

function cipher.modExp(base, exp, mod)
    local result = 1
    base = base % mod
    while exp > 0 do
        if exp % 2 == 1 then
            result = (result * base) % mod
        end
        exp = math.floor(exp / 2)
        base = (base * base) % mod
    end
    return result
end

local function millerRabin(n, k)
    if n == 2 or n == 3 then return true end
    if n < 2 or bit.band(n, 1) == 0 then return false end

    local s = 0
    local d = n - 1
    while bit.band(d, 1) == 0 do
        d = bit.rshift(d, 1)
        s = s + 1
    end

    for _ = 1, k do
        local a = math.random(2, n - 2)
        local x = cipher.modExp(a, d, n)

        if x ~= 1 and x ~= n - 1 then
            local isComposite = true
            for _ = 1, s - 1 do
                x = cipher.modExp(x, 2, n)
                if x == n - 1 then
                    isComposite = false
                    break
                end
            end

            if isComposite then
                return false
            end
        end
    end

    return true
end

local function isDivisibleBy3(n)
    --n = decimalToBinary(n)
    local oddCount, evenCount = 0, 0
    local position = 0

    while n > 0 do
        local currentbit = n % 2
        if bit.band(position, 1) == 0 then
            evenCount = evenCount + currentbit
        else
            oddCount = oddCount + currentbit
        end
        n = math.floor(bit.rshift(n, 1))
        position = position + 1
    end

    return math.abs(oddCount - evenCount) % 3 == 0
end


local function generatePrime(bits)
    local attempts = 0
    local valid = false
    while true do
        attempts = attempts + 1
        local candidate = generateRandomBits(bits)
        if not isDivisibleBy3(candidate) then
            valid = millerRabin(candidate, 60)
        end
        if valid then
            --print("Número primo encontrado en intento:", attempts)
            return candidate
        end
        os.sleep(0.1)
    end
end

local function factorize(n)
    local factors = {}
    local d = 2
    while d^2 <= n do
        while (n % d) == 0 do
            factors[d] = true
            n = math.floor(n / d)
        end
        d = d + 1
    end
    if n > 1 then
        factors[n] = true
    end
    return factors
end

local function isPrimitiveRoot(g, p)
    local factors = factorize(p - 1)
    for factor in pairs(factors) do
        if (g ^ math.floor((p - 1) / factor)) % p == 1 then
            return false
        end
    end
    return true
end

local function findPrimitiveRoot(p)
    for g = 2, p - 1 do
        if isPrimitiveRoot(g, p) then
            return g
        end
    end
end

local function generateSecretNumber(p)
    return math.random(1, p - 1)
end

function cipher.generateSecrets(session)
    local p = generatePrime(27)
    local g = findPrimitiveRoot(p)
    local a = generateSecretNumber(p)
    session.p = p
    session.private_key = a
    session.public_key = cipher.modExp(g, a, p)
end

local H = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
}
local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

local function rightRotate(value, bits)
    return bit.bor(bit.rshift(value, bits), bit.lshift(value, 32 - bits))
end

local function sha256Compress(chunk,H_copy)
    local W = {}
    for i = 1, 16 do
        W[i] = chunk[i] or 0
    end
    for i = 17, 64 do
        local s0 = bit.bxor(rightRotate(W[i-15], 7), rightRotate(W[i-15], 18), bit.rshift(W[i-15], 3))
        local s1 = bit.bxor(rightRotate(W[i-2], 17), rightRotate(W[i-2], 19), bit.rshift(W[i-2], 10))
        W[i] = (W[i-16] + s0 + W[i-7] + s1) % 0x100000000
    end

    local a, b, c, d, e, f, g, h = table.unpack(H)


    for i = 1, #K do
        local S1 = bit.bxor(rightRotate(e, 6), rightRotate(e, 11), rightRotate(e, 25))
        local ch = bit.bxor(bit.band(e, f), bit.band(bit.bnot(e), g))
        local temp1 = h + S1 + ch + K[i] + (W[i] or 0)
        local S0 = bit.bxor(rightRotate(a, 2), rightRotate(a, 13), rightRotate(a, 22))
        local maj = bit.bxor(bit.band(a, b), bit.band(a, c), bit.band(b, c))
        local temp2 = S0 + maj

        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2
    end

    H_copy[1] = bit.band(H_copy[1] + a, 0xFFFFFFFF)
    H_copy[2] = bit.band(H_copy[2] + b, 0xFFFFFFFF)
    H_copy[3] = bit.band(H_copy[3] + c, 0xFFFFFFFF)
    H_copy[4] = bit.band(H_copy[4] + d, 0xFFFFFFFF)
    H_copy[5] = bit.band(H_copy[5] + e, 0xFFFFFFFF)
    H_copy[6] = bit.band(H_copy[6] + f, 0xFFFFFFFF)
    H_copy[7] = bit.band(H_copy[7] + g, 0xFFFFFFFF)
    H_copy[8] = bit.band(H_copy[8] + h, 0xFFFFFFFF)
end

function cipher.sha256(message)
    local paddedMessage = {}
    table.insert(paddedMessage, "\x80")
    while (#paddedMessage % 64) ~= 56 do
        table.insert(paddedMessage, "\x00")
    end

    local bitLen = #message * 8
    table.insert(paddedMessage, string.pack(">I8", bitLen))

    local H_copy = {table.unpack(H)}
    for i = 1, #paddedMessage, 64 do
        local chunk = {string.byte(paddedMessage[i], i, i + 63)}
        sha256Compress(chunk, H_copy)
    end

    local digest = ""
    for i = 1, 8 do
        digest = digest .. string.format("%08x", H_copy[i])
    end
    return digest
end

function cipher.generateSalt(length)
    local salt = ""
    for _ = 1, length do
        salt = salt .. string.char(math.random(0, 255))
    end
    return salt
end

local function deriveKey(secret, salt)
    if not secret or not salt then
        return ""
    end
    local input = secret .. salt
    local hash = cipher.sha256(input)
    return hash:sub(1, 16)
end

local function xor(a, b)
    local result = {}
    for i = 1, #a do
        result[i] = string.char(bit.bxor(string.byte(a, i), string.byte(b, (i - 1) % #b + 1)))
    end
    return table.concat(result)
end
function cipher.encryptAES(message, key, salt)
    key = deriveKey(key, salt)

    local iv = ""
    for _ = 1, 16 do
        iv = iv .. string.char(math.random(0, 255))
    end

    local fillLength = 16 - (#message % 16)
    message = message .. string.rep(string.char(fillLength), fillLength)


    local blocks = {}
    for i = 1, #message, 16 do
        table.insert(blocks, message:sub(i, i + 15))
    end


    local encryptMessage = iv
    for _, block in ipairs(blocks) do
        local previousBlock = encryptMessage:sub(-16)
        local encryptBlock = xor(block, previousBlock)
        encryptMessage = encryptMessage .. encryptBlock
    end

    return encryptMessage
end

function cipher.decryptAES(encryptMessage, key, salt)
    key = deriveKey(key, salt)

    local blocks = {}
    for i = 1, #encryptMessage, 16 do
        table.insert(blocks, encryptMessage:sub(i, i + 15))
    end

    local _ = blocks[1]
    local decryptMessage = ""


    for i = 2, #blocks do
        local block = blocks[i]
        local previousBlock = blocks[i - 1]
        local decryptBlock = ""

        for j = 1, 16 do
            local decryptByte = bit.bxor(string.byte(block, j), string.byte(previousBlock, j))
            decryptBlock = decryptBlock .. string.char(decryptByte)
        end

        decryptMessage = decryptMessage .. decryptBlock
    end

    local fillLength = string.byte(decryptMessage:sub(-1))
    decryptMessage = decryptMessage:sub(1, -fillLength - 1)

    return decryptMessage
end

return cipher
