local huffman = {}
local node = require("/protocol/lib/compress/huffmanNode")
local tree = require("/protocol/lib/compress/huffmanTree")

local function serialize(t, indent)
    indent = indent or ""
    local result = "{\n"
    for key, value in pairs(t) do
        local key_str = key
        local value_str = value
        if type(value) == "string" then
            value_str = '"' .. value .. '"'
        end

        result = result .. indent .. "  " .. key_str .. " = " .. value_str .. ",\n"
    end
    result = result:sub(1, -2)
    result = result .. "\n" .. indent .. "}"
    return result
end

local function deserialize(str)
    local func = load("return " .. str)
    if not func then return end
    return func()
end


local function generateFR(data)
    local frecuencyTable = {}
    for _, character in utf8.codes(data) do
        local chara = utf8.char(character)
        if frecuencyTable[chara] then
            frecuencyTable[chara] = frecuencyTable[chara] + 1
        else
            frecuencyTable[chara] = 1
        end
    end
    local frecuencyList = {}
    for char, freq in pairs(frecuencyTable) do
        table.insert(frecuencyList, node:new(char, freq))
    end

    return frecuencyList
end

local function generateHuffmanTree(frecuencyList)
    local root = tree:new()
    root:generateHuffmanTree(frecuencyList)
    return root
end

local function generateHuffmandecode(associativeTable)
    if not associativeTable or type(associativeTable) ~= "table" then return end

    local t = {}
    for key, value in pairs(associativeTable) do
        t[value] = key
    end
    return t
end

function huffman.compress(data)
    if not data then return end
    if type(data) == "table" then data = serialize(data) end
    if type(data) == "number" then data = tostring(data) end

    local root = generateHuffmanTree(generateFR(data))
    local associativeTable = root:generateHuffmanCode(root:getRoot())
    local compressData = ""
    for chara in string.gmatch(data, ".") do
        compressData = compressData .. associativeTable[chara]
    end
    return compressData, associativeTable
end

function huffman.decompress(compressData, associativeTable, dataType)
    if not compressData or not associativeTable then return end

    associativeTable = generateHuffmandecode(associativeTable)
    if not associativeTable or type(associativeTable) ~= "table" then return end

    local decompressedData = ""
    local currentBits = ""

    for i = 1, #compressData do
        local bit = compressData:sub(i, i)
        currentBits = currentBits .. bit

        if associativeTable[currentBits] then
            decompressedData = decompressedData .. associativeTable[currentBits]
            currentBits = ""
        end
    end
    if dataType == "table" then
        return deserialize(decompressedData)
    elseif dataType == "number" then
        return tonumber(decompressedData)
    else
        return decompressedData
    end
end

return huffman
