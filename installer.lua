local mitpUrl = "https://raw.githubusercontent.com/DarThunder/Minecraft-Item-Transfer-Protocol/refs/heads/main/src/latest/"
local installDir = "protocol/"

local function checkInternet()
    local testUrl = "http://www.google.com"
    local status = http.get(testUrl)
    if status then
        print("Internet connection checked.")
        return true
    else
        print("Could not establish internet connection.")
        return false
    end
end

local function ensureDirectory(dir)
    if not fs.exists(dir) then
        fs.makeDir(dir)
        print(string.format("Directory '%s' created.", dir))
    end
end

local function createSubdirectories(path)
    local dirs = {}
    local currentPath = ""

    for dir in string.gmatch(path, "[^/]+") do
        currentPath = currentPath .. dir .. "/"
        if not fs.exists(currentPath) then
            fs.makeDir(currentPath)
            table.insert(dirs, currentPath)
            print(string.format("Directory '%s' created.", currentPath))
        end
    end

    return dirs
end

if not checkInternet() then
    return
end

local modules = {
    "MITP",
    "lib/cipher/encryptLib",
    "lib/compress/huffman",
    "lib/compress/huffmanNode",
    "lib/compress/huffmanTree",
    "lib/network/Tcp",
    "lib/network/client",
    "lib/network/server",
    "lib/network/socket",
    "lib/utils/dataUtils",
    "lib/utils/validLib",
    "lib/var/server"
}

ensureDirectory(installDir)

local success = true

print("Downloading MITP modules...")
for _, currentModule in ipairs(modules) do
    print(string.format("Trying to install module '%s.lua'", currentModule))
    local url = mitpUrl .. currentModule .. ".lua"

    local fullPath = installDir .. currentModule
    local pathWithoutFile = string.match(fullPath, "(.+)/[^/]+$")
    createSubdirectories(pathWithoutFile)

    local response = http.get(url)
    if response then
        local content = response.readAll()
        response.close()
        local file = fs.open(fullPath .. ".lua", "w")
        if file then
            file.write(content)
            file.close()
            print(string.format("Module '%s.lua' installed successfully.", currentModule))
        else
            print(string.format("Failed to write module '%s.lua'.", currentModule))
            success = false
        end
    else
        print(string.format("Failed to download '%s.lua'.", currentModule))
        success = false
    end
end
if success then shell.run("rm", "installer.lua") else shell.run("rm", installDir) end
print(success and "MITP protocol installed correctly" or "Could not install MITP protocol, check your internet connection and try again.")