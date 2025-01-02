local node = {}
local nodeMethods = {}

function node:new(chara, freq)
    local cNode = {}
    setmetatable(cNode, {__index = nodeMethods})
    cNode.chara = chara
    cNode.freq = freq
    cNode.rNode = nil
    cNode.lNode = nil
    return cNode
end

function nodeMethods:setFreq(freq)
    self.freq = freq
end

function nodeMethods:setChara(chara)
    self.chara = chara
end

function nodeMethods:setRightNode(rNode)
    self.rNode = rNode
end

function nodeMethods:setLeftNode(lNode)
    self.lNode = lNode
end

function nodeMethods:getFreq()
    return self.freq
end

function nodeMethods:getChara()
    return self.chara
end

function nodeMethods:getRightNode()
    return self.rNode
end

function nodeMethods:getLeftNode()
    return self.lNode
end

return node
