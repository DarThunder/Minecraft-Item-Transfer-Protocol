local bit = require("bit32")

local cipher = {}
math.randomseed(math.randomseed(os.time() + tonumber(tostring(os.clock()):reverse():sub(1, 5))))

local function mult(n, m)
    local result = 0
    while m > 0 do
        if bit.band(m, 1) == 1 then
            result = result + n
        end
        n = bit.lshift(n, 1)
        m = bit.rshift(m, 1)
    end
    return result
end

local function binaryToDecimal(binaryString)
    local decimal = 0
    local length = #binaryString

    for i = 1, length do
        local currentBit = tonumber(binaryString:sub(i, i))

        local power = length - i

        decimal = decimal + currentBit * (2 ^ power)
    end
    return decimal
end

local function generateRandomBits(n)
    local bits = {}

    bits[1] = 1
    bits[n] = 1

    for i = 2, n - 1 do
        bits[i] = math.random(0, 1)
    end

    local bitString = table.concat(bits)
    return binaryToDecimal(bitString)
end

function cipher.modExp(base, exp, mod)
    local result = 1
    base = base % mod
    while exp > 0 do
        if bit.band(exp, 1) == 1 then
            result = (result * base) % mod
        end
        exp = bit.rshift(exp, 1)
        base = (base * base) % mod
    end
    return result
end

local function millerRabin(n, k, valid)
    local s = 0
    local d = n - 1
    while bit.band(d, 1) == 0 do
        d = bit.rshift(d, 1)
        s = s + 1
    end

    for _ = 1, k do
        local a = math.random(2, n - 2)
        local x = cipher.modExp(a, d, n)
        local isComposite = true
        if x ~= 1 and x ~= n - 1 then
            for _ = 1, s - 1 do
                x = cipher.modExp(x, 2, n)
                if x == n - 1 then
                    isComposite = false
                    break
                end
            end

            if isComposite then
                table.insert(valid, false)
                return
            end
        end
    end

    table.insert(valid, n)
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
        n = bit.rshift(n, 1)
        position = position + 1
    end

    return math.abs(oddCount - evenCount) % 3 == 0
end

local function generatePrime(bits)
    local sample = {}
    local valid = {}
    while #sample < 50 do
        local candidate = generateRandomBits(bits)
        if not isDivisibleBy3(candidate) then
            table.insert(sample, function ()
                millerRabin(candidate, 60, valid)
            end)
        end
    end
    parallel.waitForAll(table.unpack(sample))
    for _, value in ipairs(valid) do
        if value then
            return value
        end
    end
    return generatePrime(bits)
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
        if cipher.modExp(g, math.floor((p - 1) / factor), p) == 1 then
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

function cipher.generateSecretNumber(p)
    return math.random(1, p - 1)
end

function cipher.generateSecrets(session)
    local p = generatePrime(27)
    local g = findPrimitiveRoot(p)
    local a = cipher.generateSecretNumber(p)
    session.g = g
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

local function sha256Compress(chunk, H_copy)
    local W = {}
    for i = 1, 16 do
        W[i] = chunk[i] or 0
    end
    for i = 17, 64 do
        local s0 = bit.bxor(rightRotate(W[i-15], 7), rightRotate(W[i-15], 18), bit.rshift(W[i-15], 3))
        local s1 = bit.bxor(rightRotate(W[i-2], 17), rightRotate(W[i-2], 19), bit.rshift(W[i-2], 10))
        W[i] = (W[i-16] + s0 + W[i-7] + s1) % 0x100000000
    end

    local a, b, c, d, e, f, g, h = table.unpack(H_copy)

    for i = 1, 64 do
        local S1 = bit.bxor(rightRotate(e, 6), rightRotate(e, 11), rightRotate(e, 25))
        local ch = bit.bxor(bit.band(e, f), bit.band(bit.bnot(e), g))
        local temp1 = (h + S1 + ch + K[i] + W[i]) % 0x100000000
        local S0 = bit.bxor(rightRotate(a, 2), rightRotate(a, 13), rightRotate(a, 22))
        local maj = bit.bxor(bit.band(a, b), bit.band(a, c), bit.band(b, c))
        local temp2 = (S0 + maj) % 0x100000000

        h = g
        g = f
        f = e
        e = (d + temp1) % 0x100000000
        d = c
        c = b
        b = a
        a = (temp1 + temp2) % 0x100000000
    end

    for i = 1, 8 do
        H_copy[i] = (H_copy[i] + ({a, b, c, d, e, f, g, h})[i]) % 0x100000000
    end
end

function cipher.sha256(message)
    local messageLen = #message
    local paddedMessage = message .. "\x80"
    while (#paddedMessage % 64) ~= 56 do
        paddedMessage = paddedMessage .. "\x00"
    end
    paddedMessage = paddedMessage .. string.pack(">I8", messageLen * 8)

    local H_copy = {table.unpack(H)}
    for i = 1, #paddedMessage, 64 do
        local chunk = {string.unpack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4", paddedMessage:sub(i, i + 63))}
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


local S_BOX = {
    ["0"] = {["0"] = 0x63, ["1"] = 0x7c, ["2"] = 0x77, ["3"] = 0x7b, ["4"] = 0xf2, ["5"] = 0x6b, ["6"] = 0x6f, ["7"] = 0xc5, ["8"] = 0x30, ["9"] = 0x01, ["a"] = 0x67, ["b"] = 0x2b, ["c"] = 0xfe, ["d"] = 0xd7, ["e"] = 0xab, ["f"] = 0x76},
    ["1"] = {["0"] = 0xca, ["1"] = 0x82, ["2"] = 0xc9, ["3"] = 0x7d, ["4"] = 0xfa, ["5"] = 0x59, ["6"] = 0x47, ["7"] = 0xf0, ["8"] = 0xad, ["9"] = 0xd4, ["a"] = 0xa2, ["b"] = 0xaf, ["c"] = 0x9c, ["d"] = 0xa4, ["e"] = 0x72, ["f"] = 0xc0},
    ["2"] = {["0"] = 0xb7, ["1"] = 0xfd, ["2"] = 0x93, ["3"] = 0x26, ["4"] = 0x36, ["5"] = 0x3f, ["6"] = 0xf7, ["7"] = 0xcc, ["8"] = 0x34, ["9"] = 0xa5, ["a"] = 0xe5, ["b"] = 0xf1, ["c"] = 0x71, ["d"] = 0xd8, ["e"] = 0x31, ["f"] = 0x15},
    ["3"] = {["0"] = 0x04, ["1"] = 0xc7, ["2"] = 0x23, ["3"] = 0xc3, ["4"] = 0x18, ["5"] = 0x96, ["6"] = 0x05, ["7"] = 0x9a, ["8"] = 0x07, ["9"] = 0x12, ["a"] = 0x80, ["b"] = 0xe2, ["c"] = 0xeb, ["d"] = 0x27, ["e"] = 0xb2, ["f"] = 0x75},
    ["4"] = {["0"] = 0x09, ["1"] = 0x83, ["2"] = 0x2c, ["3"] = 0x1a, ["4"] = 0x1b, ["5"] = 0x6e, ["6"] = 0x5a, ["7"] = 0xa0, ["8"] = 0x52, ["9"] = 0x3b, ["a"] = 0xd6, ["b"] = 0xb3, ["c"] = 0x29, ["d"] = 0xe3, ["e"] = 0x2f, ["f"] = 0x84},
    ["5"] = {["0"] = 0x53, ["1"] = 0xd1, ["2"] = 0x00, ["3"] = 0xed, ["4"] = 0x20, ["5"] = 0xfc, ["6"] = 0xb1, ["7"] = 0x5b, ["8"] = 0x6a, ["9"] = 0xcb, ["a"] = 0xbe, ["b"] = 0x39, ["c"] = 0x4a, ["d"] = 0x4c, ["e"] = 0x58, ["f"] = 0xcf},
    ["6"] = {["0"] = 0xd0, ["1"] = 0xef, ["2"] = 0xaa, ["3"] = 0xfb, ["4"] = 0x43, ["5"] = 0x4d, ["6"] = 0x33, ["7"] = 0x85, ["8"] = 0x45, ["9"] = 0xf9, ["a"] = 0x02, ["b"] = 0x7f, ["c"] = 0x50, ["d"] = 0x3c, ["e"] = 0x9f, ["f"] = 0xa8},
    ["7"] = {["0"] = 0x51, ["1"] = 0xa3, ["2"] = 0x40, ["3"] = 0x8f, ["4"] = 0x92, ["5"] = 0x9d, ["6"] = 0x38, ["7"] = 0xf5, ["8"] = 0xbc, ["9"] = 0xb6, ["a"] = 0xda, ["b"] = 0x21, ["c"] = 0x10, ["d"] = 0xff, ["e"] = 0xf3, ["f"] = 0xd2},
    ["8"] = {["0"] = 0xcd, ["1"] = 0x0c, ["2"] = 0x13, ["3"] = 0xec, ["4"] = 0x5f, ["5"] = 0x97, ["6"] = 0x44, ["7"] = 0x17, ["8"] = 0xc4, ["9"] = 0xa7, ["a"] = 0x7e, ["b"] = 0x3d, ["c"] = 0x64, ["d"] = 0x5d, ["e"] = 0x19, ["f"] = 0x73},
    ["9"] = {["0"] = 0x60, ["1"] = 0x81, ["2"] = 0x4f, ["3"] = 0xdc, ["4"] = 0x22, ["5"] = 0x2a, ["6"] = 0x90, ["7"] = 0x88, ["8"] = 0x46, ["9"] = 0xee, ["a"] = 0xb8, ["b"] = 0x14, ["c"] = 0xde, ["d"] = 0x5e, ["e"] = 0x0b, ["f"] = 0xdb},
    ["a"] = {["0"] = 0xe0, ["1"] = 0x32, ["2"] = 0x3a, ["3"] = 0x0a, ["4"] = 0x49, ["5"] = 0x06, ["6"] = 0x24, ["7"] = 0x5c, ["8"] = 0xc2, ["9"] = 0xd3, ["a"] = 0xac, ["b"] = 0x62, ["c"] = 0x91, ["d"] = 0x95, ["e"] = 0xe4, ["f"] = 0x79},
    ["b"] = {["0"] = 0xe7, ["1"] = 0xc8, ["2"] = 0x37, ["3"] = 0x6d, ["4"] = 0x8d, ["5"] = 0xd5, ["6"] = 0x4e, ["7"] = 0xa9, ["8"] = 0x6c, ["9"] = 0x56, ["a"] = 0xf4, ["b"] = 0xea, ["c"] = 0x65, ["d"] = 0x7a, ["e"] = 0xae, ["f"] = 0x08},
    ["c"] = {["0"] = 0xba, ["1"] = 0x78, ["2"] = 0x25, ["3"] = 0x2e, ["4"] = 0x1c, ["5"] = 0xa6, ["6"] = 0xb4, ["7"] = 0xc6, ["8"] = 0xe8, ["9"] = 0xdd, ["a"] = 0x74, ["b"] = 0x1f, ["c"] = 0x4b, ["d"] = 0xbd, ["e"] = 0x8b, ["f"] = 0x8a},
    ["d"] = {["0"] = 0x70, ["1"] = 0x3e, ["2"] = 0xb5, ["3"] = 0x66, ["4"] = 0x48, ["5"] = 0x03, ["6"] = 0xf6, ["7"] = 0x0e, ["8"] = 0x61, ["9"] = 0x35, ["a"] = 0x57, ["b"] = 0xb9, ["c"] = 0x86, ["d"] = 0xc1, ["e"] = 0x1d, ["f"] = 0x9e},
    ["e"] = {["0"] = 0xe1, ["1"] = 0xf8, ["2"] = 0x98, ["3"] = 0x11, ["4"] = 0x69, ["5"] = 0xd9, ["6"] = 0x8e, ["7"] = 0x94, ["8"] = 0x9b, ["9"] = 0x1e, ["a"] = 0x87, ["b"] = 0xe9, ["c"] = 0xce, ["d"] = 0x55, ["e"] = 0x28, ["f"] = 0xdf},
    ["f"] = {["0"] = 0x8c, ["1"] = 0xa1, ["2"] = 0x89, ["3"] = 0x0d, ["4"] = 0xbf, ["5"] = 0xe6, ["6"] = 0x42, ["7"] = 0x68, ["8"] = 0x41, ["9"] = 0x99, ["a"] = 0x2d, ["b"] = 0x0f, ["c"] = 0xb0, ["d"] = 0x54, ["e"] = 0xbb, ["f"] = 0x16}
}

local INV_S_BOX = {
    ["0"] = {["0"] = 0x52, ["1"] = 0x09, ["2"] = 0x6a, ["3"] = 0xd5, ["4"] = 0x30, ["5"] = 0x36, ["6"] = 0xa5, ["7"] = 0x38, ["8"] = 0xbf, ["9"] = 0x40, ["a"] = 0xa3, ["b"] = 0x9e, ["c"] = 0x81, ["d"] = 0xf3, ["e"] = 0xd7, ["f"] = 0xfb},
    ["1"] = {["0"] = 0x7c, ["1"] = 0xe3, ["2"] = 0x39, ["3"] = 0x82, ["4"] = 0x9b, ["5"] = 0x2f, ["6"] = 0xff, ["7"] = 0x87, ["8"] = 0x34, ["9"] = 0x8e, ["a"] = 0x43, ["b"] = 0x44, ["c"] = 0xc4, ["d"] = 0xde, ["e"] = 0xe9, ["f"] = 0xcb},
    ["2"] = {["0"] = 0x54, ["1"] = 0x7b, ["2"] = 0x94, ["3"] = 0x32, ["4"] = 0xa6, ["5"] = 0xc2, ["6"] = 0x23, ["7"] = 0x3d, ["8"] = 0xee, ["9"] = 0x4c, ["a"] = 0x95, ["b"] = 0x0b, ["c"] = 0x42, ["d"] = 0xfa, ["e"] = 0xc3, ["f"] = 0x4e},
    ["3"] = {["0"] = 0x08, ["1"] = 0x2e, ["2"] = 0xa1, ["3"] = 0x66, ["4"] = 0x28, ["5"] = 0xd9, ["6"] = 0x24, ["7"] = 0xb2, ["8"] = 0x76, ["9"] = 0x5b, ["a"] = 0xa2, ["b"] = 0x49, ["c"] = 0x6d, ["d"] = 0x8b, ["e"] = 0xd1, ["f"] = 0x25},
    ["4"] = {["0"] = 0x72, ["1"] = 0xf8, ["2"] = 0xf6, ["3"] = 0x64, ["4"] = 0x86, ["5"] = 0x68, ["6"] = 0x98, ["7"] = 0x16, ["8"] = 0xd4, ["9"] = 0xa4, ["a"] = 0x5c, ["b"] = 0xcc, ["c"] = 0x5d, ["d"] = 0x65, ["e"] = 0xb6, ["f"] = 0x92},
    ["5"] = {["0"] = 0x6c, ["1"] = 0x70, ["2"] = 0x48, ["3"] = 0x50, ["4"] = 0xfd, ["5"] = 0xed, ["6"] = 0xb9, ["7"] = 0xda, ["8"] = 0x5e, ["9"] = 0x15, ["a"] = 0x46, ["b"] = 0x57, ["c"] = 0xa7, ["d"] = 0x8d, ["e"] = 0x9d, ["f"] = 0x84},
    ["6"] = {["0"] = 0x90, ["1"] = 0xd8, ["2"] = 0xab, ["3"] = 0x00, ["4"] = 0x8c, ["5"] = 0xbc, ["6"] = 0xd3, ["7"] = 0x0a, ["8"] = 0xf7, ["9"] = 0xe4, ["a"] = 0x58, ["b"] = 0x05, ["c"] = 0xb8, ["d"] = 0xb3, ["e"] = 0x45, ["f"] = 0x06},
    ["7"] = {["0"] = 0xd0, ["1"] = 0x2c, ["2"] = 0x1e, ["3"] = 0x8f, ["4"] = 0xca, ["5"] = 0x3f, ["6"] = 0x0f, ["7"] = 0x02, ["8"] = 0xc1, ["9"] = 0xaf, ["a"] = 0xbd, ["b"] = 0x03, ["c"] = 0x01, ["d"] = 0x13, ["e"] = 0x8a, ["f"] = 0x6b},
    ["8"] = {["0"] = 0x3a, ["1"] = 0x91, ["2"] = 0x11, ["3"] = 0x41, ["4"] = 0x4f, ["5"] = 0x67, ["6"] = 0xdc, ["7"] = 0xea, ["8"] = 0x97, ["9"] = 0xf2, ["a"] = 0xcf, ["b"] = 0xce, ["c"] = 0xf0, ["d"] = 0xb4, ["e"] = 0xe6, ["f"] = 0x73},
    ["9"] = {["0"] = 0x96, ["1"] = 0xac, ["2"] = 0x74, ["3"] = 0x22, ["4"] = 0xe7, ["5"] = 0xad, ["6"] = 0x35, ["7"] = 0x85, ["8"] = 0xe2, ["9"] = 0xf9, ["a"] = 0x37, ["b"] = 0xe8, ["c"] = 0x1c, ["d"] = 0x75, ["e"] = 0xdf, ["f"] = 0x6e},
    ["a"] = {["0"] = 0x47, ["1"] = 0xf1, ["2"] = 0x1a, ["3"] = 0x71, ["4"] = 0x1d, ["5"] = 0x29, ["6"] = 0xc5, ["7"] = 0x89, ["8"] = 0x6f, ["9"] = 0xb7, ["a"] = 0x62, ["b"] = 0x0e, ["c"] = 0xaa, ["d"] = 0x18, ["e"] = 0xbe, ["f"] = 0x1b},
    ["b"] = {["0"] = 0xfc, ["1"] = 0x56, ["2"] = 0x3e, ["3"] = 0x4b, ["4"] = 0xc6, ["5"] = 0xd2, ["6"] = 0x79, ["7"] = 0x20, ["8"] = 0x9a, ["9"] = 0xdb, ["a"] = 0xc0, ["b"] = 0xfe, ["c"] = 0x78, ["d"] = 0xcd, ["e"] = 0x5a, ["f"] = 0xf4},
    ["c"] = {["0"] = 0x1f, ["1"] = 0xdd, ["2"] = 0xa8, ["3"] = 0x33, ["4"] = 0x88, ["5"] = 0x07, ["6"] = 0xc7, ["7"] = 0x31, ["8"] = 0xb1, ["9"] = 0x12, ["a"] = 0x10, ["b"] = 0x59, ["c"] = 0x27, ["d"] = 0x80, ["e"] = 0xec, ["f"] = 0x5f},
    ["d"] = {["0"] = 0x60, ["1"] = 0x51, ["2"] = 0x7f, ["3"] = 0xa9, ["4"] = 0x19, ["5"] = 0xb5, ["6"] = 0x4a, ["7"] = 0x0d, ["8"] = 0x2d, ["9"] = 0xe5, ["a"] = 0x7a, ["b"] = 0x9f, ["c"] = 0x93, ["d"] = 0xc9, ["e"] = 0x9c, ["f"] = 0xef},
    ["e"] = {["0"] = 0xa0, ["1"] = 0xe0, ["2"] = 0x3b, ["3"] = 0x4d, ["4"] = 0xae, ["5"] = 0x2a, ["6"] = 0xf5, ["7"] = 0xb0, ["8"] = 0xc8, ["9"] = 0xeb, ["a"] = 0xbb, ["b"] = 0x3c, ["c"] = 0x83, ["d"] = 0x53, ["e"] = 0x99, ["f"] = 0x61},
    ["f"] = {["0"] = 0x17, ["1"] = 0x2b, ["2"] = 0x04, ["3"] = 0x7e, ["4"] = 0xba, ["5"] = 0x77, ["6"] = 0xd6, ["7"] = 0x26, ["8"] = 0xe1, ["9"] = 0x69, ["a"] = 0x14, ["b"] = 0x63, ["c"] = 0x55, ["d"] = 0x21, ["e"] = 0x0c, ["f"] = 0x7d}
}

local MATRIX = {
    {0x03, 0x0b}, {0x01, 0x0d}, {0x01, 0x09}, {0x02, 0x0e}
}

local RCON = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
}

local function deriveKey(secret)
    if not secret then
        return ""
    end
    local hash = cipher.sha256(secret)
    return hash:sub(17, 32)
end

local function bxor(...)
    local args = {...}
    local result = args[1]
    for i = 2, #args do
        result = bit.bxor(result, args[i])
    end
    return result
end

local function xor(block1, block2)
    local result = {}
    for i = 1, #block1 do
        result[i] = string.char(bit.bxor(string.byte(block1, i), string.byte(block2, i)))
    end
    return table.concat(result)
end

local function toMatrix(plainText)
    local matrix = {}
    for i = 1, 4 do
        matrix[i] = {}
        for j = 1, 4 do
            matrix[i][j] = string.byte(plainText, (i - 1) * 4 + j)
        end
    end
    return matrix
end

local function fromMatrix(matrix)
    local block = {}
    for i = 1, 4 do
        for j = 1, 4 do
            block[#block + 1] = string.char(matrix[i][j])
        end
    end

    return table.concat(block)
end

local function gmul(a, b)
    local returnValue = 0
    local temp = 0
    while a ~= 0 do
        if bit.band(a, 1) ~= 0 then
            returnValue = bit.bxor(returnValue, b)
        end
        temp = bit.band(b, 0x80)
        b = bit.lshift(b, 1)
        if temp ~= 0 then
            b = bit.bxor(b, 0x1b)
        end
        a = bit.rshift(bit.band(a, 0xff), 1)
    end
    return bit.band(returnValue, 0xff)
end

local function rotWord(word)
    return { word[2], word[3], word[4], word[1]}
end

local function KeyExpansion(key)
    local roundKeys = {}

    key = toMatrix(key)
    roundKeys[1] = key

    for round = 2, 11 do
        roundKeys[round] = {}
        for col = 1, 4 do
            roundKeys[round][col] = {}
            local rotCol = rotWord(roundKeys[round - 1][col])
            for row = 1, 4 do
                local hex = string.format("%02x", rotCol[row])
                roundKeys[round][col][row] = bit.bxor(S_BOX[hex:sub(1, 1)][hex:sub(2, 2)], RCON[round - 1])
            end
        end
    end

    return roundKeys
end

local function subBytes(block, decrypt)
    local box = decrypt and S_BOX or INV_S_BOX
    local newBlock = {}
    for i = 1, 4 do
        newBlock[i] = {}
        for j = 1, 4 do
            local hex = string.format("%02x", block[i][j])
            local row = hex:sub(1, 1)
            local col = hex:sub(2, 2)
            newBlock[i][j] = box[row][col]
        end
    end
    return newBlock
end

local function shiftRows(block)
    block[2] = {block[2][2], block[2][3], block[2][4], block[2][1]}

    block[3] = {block[3][3], block[3][4], block[3][1], block[3][2]}

    block[4] = {block[4][4], block[4][1], block[4][2], block[4][3]}
end

local function inverseShiftRows(block)
    block[2] = {block[2][4], block[2][1], block[2][2], block[2][3]}

    block[3] = {block[3][3], block[3][4], block[3][1], block[3][2]}

    block[4] = {block[4][2], block[4][3], block[4][4], block[4][1]}
end


local function mixColumns(state, decrypt)
    local index = (not decrypt) and 2 or 1

    local a = MATRIX[1][index]
    local b = MATRIX[2][index]
    local c = MATRIX[3][index]
    local d = MATRIX[4][index]

    local temp = {}

    for i = 1, 4 do
        temp[1] = bxor(gmul(d, state[1][i]), gmul(a, state[2][i]), gmul(b, state[3][i]), gmul(c, state[4][i]))
        temp[2] = bxor(gmul(c, state[1][i]), gmul(d, state[2][i]), gmul(a, state[3][i]), gmul(b, state[4][i]))
        temp[3] = bxor(gmul(b, state[1][i]), gmul(c, state[2][i]), gmul(d, state[3][i]), gmul(a, state[4][i]))
        temp[4] = bxor(gmul(a, state[1][i]), gmul(b, state[2][i]), gmul(c, state[3][i]), gmul(d, state[4][i]))
        for j = 1, 4 do
            state[j][i] = temp[j]
        end
    end
end

local function addRoundKey(block, roundKey)
    for i = 1, 4 do
        for j = 1, 4 do
            block[i][j] = bit.bxor(block[i][j], roundKey[i][j])
        end
    end
end

local function encryptBlock(block, key)
    block = toMatrix(block)

    local subKeys = KeyExpansion(key)
    addRoundKey(block, subKeys[1])

    for round = 2, 11 do
        block = subBytes(block)
        shiftRows(block)

        if round < 11 then
            mixColumns(block)
        end

        addRoundKey(block, subKeys[round])
    end
    return fromMatrix(block)
end


local function decryptBlock(block, key)
    block = toMatrix(block)

    local subKey = KeyExpansion(key)
    addRoundKey(block, subKey[11])

    for round = 10, 1, -1 do
        if round < 10 then
            mixColumns(block, true)
        end
        inverseShiftRows(block)
        block = subBytes(block, true)

        addRoundKey(block, subKey[round])
    end
    return fromMatrix(block)
end

function cipher.encryptAES(message, secret)
    local key = deriveKey(secret)

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

    local previousBlock = iv
    local encryptMessage = ""

    for _, block in ipairs(blocks) do
        local xorBlock = xor(block, previousBlock)
        local encryptedBlock = encryptBlock(xorBlock, key)
        encryptMessage = encryptMessage .. encryptedBlock
        previousBlock = encryptedBlock
    end

    return iv .. encryptMessage
end


function cipher.decryptAES(encryptedMessage, secret)
    local key = deriveKey(secret)

    local iv = encryptedMessage:sub(1, 16)
    encryptedMessage = encryptedMessage:sub(17)

    local blocks = {}
    for i = 1, #encryptedMessage, 16 do
        table.insert(blocks, encryptedMessage:sub(i, i + 15))
    end

    local previousBlock = iv
    local decryptedMessage = ""

    for _, block in ipairs(blocks) do
        local decryptedBlock = decryptBlock(block, key)
        local xorBlock = xor(decryptedBlock, previousBlock)
        decryptedMessage = decryptedMessage .. xorBlock
        previousBlock = block
    end

    local fillLength = string.byte(decryptedMessage:sub(-1))
    if fillLength >= 1 and fillLength <= 16 then
        decryptedMessage = decryptedMessage:sub(1, -fillLength - 1)
    end

    return decryptedMessage
end

return cipher
