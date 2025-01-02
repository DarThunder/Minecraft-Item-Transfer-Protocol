local node = require("/protocol/lib/compress/huffmanNode")

local tree = {}
local treeMethods = {}

function tree:new(chara, freq)
    local bTree = {}
    setmetatable(bTree, { __index = treeMethods })
    bTree.root = node:new(chara, freq)
    return bTree
end

function treeMethods:setRoot(root)
    self.root = root
end

function treeMethods:getRoot()
    return self.root
end

function treeMethods:generateHuffmanTree(frecuencyList)
    table.sort(frecuencyList, function(a, b) return a:getFreq() < b:getFreq() end)

    for _ = 1, #frecuencyList - 1 do
        local smallest = table.remove(frecuencyList, 1)
        local secondSmallest = table.remove(frecuencyList, 1)

        local newNode = node:new(nil, smallest:getFreq() + secondSmallest:getFreq())
        newNode:setRightNode(smallest)
        newNode:setLeftNode(secondSmallest)

        table.insert(frecuencyList, newNode)
        table.sort(frecuencyList, function(a, b) return a:getFreq() < b:getFreq() end)
    end
    self:setRoot(frecuencyList[1])
end

function treeMethods:generateHuffmanCode(root, code, codes)
    if not codes then codes = {} end
    if not code then code = "" end
    if root then
        if root:getChara() then
            codes[root:getChara()] = code
        end

        treeMethods:generateHuffmanCode(root:getLeftNode(), code .. "\x00", codes)
        treeMethods:generateHuffmanCode(root:getRightNode(), code .. "\x01", codes)

    end
    return codes
end

return tree
