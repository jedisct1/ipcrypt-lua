package = "ipcrypt"
version = "1.0.0-1"

source = {
    url = "git+https://github.com/jedisct1/ipcrypt-lua.git",
    tag = "1.0.0"
}

description = {
    summary = "Pure Lua implementation of IPCrypt for IP address encryption",
    detailed = [[
        IPCrypt provides methods for IP address encryption and obfuscation.
        This pure Lua implementation supports:
        - Deterministic encryption using AES-128
        - Non-deterministic encryption using KIASU-BC (8-byte tweaks)
        - Non-deterministic encryption using AES-XTS (16-byte tweaks)
        Both IPv4 and IPv6 addresses are supported.
    ]],
    homepage = "https://github.com/jedisct1/ipcrypt-lua",
    license = "MIT",
    maintainer = "Frank Denis"
}

dependencies = {
    "lua >= 5.3"  -- Requires Lua 5.3+ for native bitwise operators
}

build = {
    type = "builtin",
    modules = {
        -- Main module
        ["ipcrypt"] = "lib/ipcrypt/init.lua",
        
        -- Utils
        ["ipcrypt.utils"] = "lib/ipcrypt/utils.lua",
        
        -- Cipher implementations
        ["ipcrypt.cipher.aes_core"] = "lib/ipcrypt/cipher/aes_core.lua",
        ["ipcrypt.cipher.aes"] = "lib/ipcrypt/cipher/aes.lua",
        ["ipcrypt.cipher.aes_xts"] = "lib/ipcrypt/cipher/aes_xts.lua",
        ["ipcrypt.cipher.kiasu_bc"] = "lib/ipcrypt/cipher/kiasu_bc.lua",
        
        -- Encryption modes
        ["ipcrypt.mode.deterministic"] = "lib/ipcrypt/mode/deterministic.lua",
        ["ipcrypt.mode.nd"] = "lib/ipcrypt/mode/nd.lua",
        ["ipcrypt.mode.ndx"] = "lib/ipcrypt/mode/ndx.lua"
    },
    install = {
        bin = {
            ["ipcrypt-keygen"] = "bin/ipcrypt-keygen"
        }
    }
}
