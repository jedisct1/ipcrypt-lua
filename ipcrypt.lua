-- ipcrypt.lua - Main module for IPCrypt Lua implementation

local ipcrypt_deterministic = require("ipcrypt_deterministic")
local ipcrypt_nd = require("ipcrypt_nd")
local ipcrypt_ndx = require("ipcrypt_ndx")
local utils = require("utils")

local ipcrypt = {
    -- Version information
    VERSION = "1.0.0",
    
    -- Export individual modules
    deterministic = ipcrypt_deterministic,
    nd = ipcrypt_nd,
    ndx = ipcrypt_ndx,
    utils = utils,
    
    -- Convenience functions
    hex_to_bytes = utils.hex_to_bytes,
    bytes_to_hex = utils.bytes_to_hex,
}

-- Deterministic encryption/decryption
function ipcrypt.encrypt_deterministic(ip_str, key)
    return ipcrypt_deterministic.encrypt(ip_str, key)
end

function ipcrypt.decrypt_deterministic(ip_str, key)
    return ipcrypt_deterministic.decrypt(ip_str, key)
end

-- Non-deterministic encryption/decryption with KIASU-BC
function ipcrypt.encrypt_nd(ip_str, key, tweak)
    return ipcrypt_nd.encrypt(ip_str, key, tweak)
end

function ipcrypt.decrypt_nd(encrypted_data, key)
    return ipcrypt_nd.decrypt(encrypted_data, key)
end

-- Non-deterministic encryption/decryption with AES-XTS
function ipcrypt.encrypt_ndx(ip_str, key, tweak)
    return ipcrypt_ndx.encrypt(ip_str, key, tweak)
end

function ipcrypt.decrypt_ndx(encrypted_data, key)
    return ipcrypt_ndx.decrypt(encrypted_data, key)
end

return ipcrypt