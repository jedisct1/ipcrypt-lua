-- ipcrypt_deterministic.lua - Deterministic IPCrypt implementation using AES-128

local utils = require("utils")
local aes = require("aes")

local ipcrypt_deterministic = {}

-- Encrypt an IP address using deterministic AES-128
function ipcrypt_deterministic.encrypt(ip_str, key)
    assert(#key == 16, "Key must be 16 bytes")
    
    -- Convert IP to 16-byte representation
    local plaintext = utils.ip_to_bytes(ip_str)
    
    -- Encrypt with AES-128
    local ciphertext = aes.encrypt(plaintext, key)
    
    -- Convert back to IP address
    return utils.bytes_to_ip(ciphertext)
end

-- Decrypt an IP address using deterministic AES-128
function ipcrypt_deterministic.decrypt(ip_str, key)
    assert(#key == 16, "Key must be 16 bytes")
    
    -- Convert IP to 16-byte representation
    local ciphertext = utils.ip_to_bytes(ip_str)
    
    -- Decrypt with AES-128
    local plaintext = aes.decrypt(ciphertext, key)
    
    -- Convert back to IP address
    return utils.bytes_to_ip(plaintext)
end

return ipcrypt_deterministic