-- ipcrypt_nd.lua - Non-deterministic IPCrypt implementation using KIASU-BC

local utils = require("ipcrypt.utils")
local kiasu_bc = require("ipcrypt.cipher.kiasu_bc")

local ipcrypt_nd = {}

-- Encrypt an IP address using KIASU-BC with an 8-byte tweak
function ipcrypt_nd.encrypt(ip_str, key, tweak)
    assert(#key == 16, "Key must be 16 bytes")
    
    -- Generate random tweak if not provided
    if not tweak then
        tweak = utils.random_bytes(8)
    end
    assert(#tweak == 8, "Tweak must be 8 bytes")
    
    -- Convert IP to 16-byte representation
    local plaintext = utils.ip_to_bytes(ip_str)
    
    -- Encrypt with KIASU-BC
    local ciphertext = kiasu_bc.encrypt(key, tweak, plaintext)
    
    -- Return tweak || ciphertext (24 bytes total)
    return tweak .. ciphertext
end

-- Decrypt an IP address encrypted with KIASU-BC
function ipcrypt_nd.decrypt(encrypted_data, key)
    assert(#key == 16, "Key must be 16 bytes")
    assert(#encrypted_data == 24, "Encrypted data must be 24 bytes (8-byte tweak + 16-byte ciphertext)")
    
    -- Split into tweak and ciphertext
    local tweak = encrypted_data:sub(1, 8)
    local ciphertext = encrypted_data:sub(9, 24)
    
    -- Decrypt with KIASU-BC
    local plaintext = kiasu_bc.decrypt(key, tweak, ciphertext)
    
    -- Convert back to IP address
    return utils.bytes_to_ip(plaintext)
end

return ipcrypt_nd