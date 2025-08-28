-- ipcrypt_ndx.lua - Non-deterministic IPCrypt implementation using AES-XTS

local utils = require("ipcrypt.utils")
local aes_xts = require("ipcrypt.cipher.aes_xts")

local ipcrypt_ndx = {}

-- Encrypt an IP address using AES-XTS with a 16-byte tweak
function ipcrypt_ndx.encrypt(ip_str, key, tweak)
    assert(#key == 32, "Key must be 32 bytes")
    
    -- Generate random tweak if not provided
    if not tweak then
        tweak = utils.random_bytes(16)
    end
    assert(#tweak == 16, "Tweak must be 16 bytes")
    
    -- Convert IP to 16-byte representation
    local plaintext = utils.ip_to_bytes(ip_str)
    
    -- Encrypt with AES-XTS
    local ciphertext = aes_xts.encrypt(key, tweak, plaintext)
    
    -- Return tweak || ciphertext (32 bytes total)
    return tweak .. ciphertext
end

-- Decrypt an IP address encrypted with AES-XTS
function ipcrypt_ndx.decrypt(encrypted_data, key)
    assert(#key == 32, "Key must be 32 bytes")
    assert(#encrypted_data == 32, "Encrypted data must be 32 bytes (16-byte tweak + 16-byte ciphertext)")
    
    -- Split into tweak and ciphertext
    local tweak = encrypted_data:sub(1, 16)
    local ciphertext = encrypted_data:sub(17, 32)
    
    -- Decrypt with AES-XTS
    local plaintext = aes_xts.decrypt(key, tweak, ciphertext)
    
    -- Convert back to IP address
    return utils.bytes_to_ip(plaintext)
end

return ipcrypt_ndx