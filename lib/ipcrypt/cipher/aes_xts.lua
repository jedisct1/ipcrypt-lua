-- aes_xts.lua - AES-XTS implementation for IPCrypt

local utils = require("ipcrypt.utils")
local aes = require("ipcrypt.cipher.aes")

local aes_xts = {}

-- AES-XTS encryption
function aes_xts.encrypt(key, tweak, plaintext)
    assert(#key == 32, "Key must be 32 bytes")
    assert(#tweak == 16, "Tweak must be 16 bytes")
    assert(#plaintext == 16, "Plaintext must be 16 bytes")
    
    -- Split key into two 16-byte keys
    local k1 = key:sub(1, 16)
    local k2 = key:sub(17, 32)
    
    -- Encrypt tweak with second key
    local et = aes.encrypt(tweak, k2)
    
    -- XOR plaintext with encrypted tweak
    local xored = utils.xor_bytes(plaintext, et)
    
    -- Encrypt with first key
    local encrypted = aes.encrypt(xored, k1)
    
    -- XOR result with encrypted tweak
    return utils.xor_bytes(encrypted, et)
end

-- AES-XTS decryption
function aes_xts.decrypt(key, tweak, ciphertext)
    assert(#key == 32, "Key must be 32 bytes")
    assert(#tweak == 16, "Tweak must be 16 bytes")
    assert(#ciphertext == 16, "Ciphertext must be 16 bytes")
    
    -- Split key into two 16-byte keys
    local k1 = key:sub(1, 16)
    local k2 = key:sub(17, 32)
    
    -- Encrypt tweak with second key
    local et = aes.encrypt(tweak, k2)
    
    -- XOR ciphertext with encrypted tweak
    local xored = utils.xor_bytes(ciphertext, et)
    
    -- Decrypt with first key
    local decrypted = aes.decrypt(xored, k1)
    
    -- XOR result with encrypted tweak
    return utils.xor_bytes(decrypted, et)
end

return aes_xts