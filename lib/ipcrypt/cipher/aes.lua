-- aes.lua - AES-128 implementation using shared core

local aes_core = require("ipcrypt.cipher.aes_core")
local aes = {}


-- Re-export expand_key for compatibility
aes.expand_key = aes_core.expand_key

-- AES-128 encryption
function aes.encrypt(plaintext, key)
    assert(#plaintext == 16, "Plaintext must be 16 bytes")
    assert(#key == 16, "Key must be 16 bytes")
    
    local round_keys = aes_core.expand_key(key)
    local state = aes_core.bytes_to_state(plaintext)
    
    -- Initial round
    for i = 1, 16 do
        state[i] = aes_core.bxor(state[i], round_keys[i])
    end
    
    -- Main rounds
    for round = 1, 9 do
        aes_core.sub_bytes(state)
        aes_core.shift_rows(state)
        aes_core.mix_columns(state)
        for i = 1, 16 do
            state[i] = aes_core.bxor(state[i], round_keys[round * 16 + i])
        end
    end
    
    -- Final round
    aes_core.sub_bytes(state)
    aes_core.shift_rows(state)
    for i = 1, 16 do
        state[i] = aes_core.bxor(state[i], round_keys[160 + i])
    end
    
    return aes_core.state_to_bytes(state)
end

-- AES-128 decryption
function aes.decrypt(ciphertext, key)
    assert(#ciphertext == 16, "Ciphertext must be 16 bytes")
    assert(#key == 16, "Key must be 16 bytes")
    
    local round_keys = aes_core.expand_key(key)
    local state = aes_core.bytes_to_state(ciphertext)
    
    -- Initial round
    for i = 1, 16 do
        state[i] = aes_core.bxor(state[i], round_keys[160 + i])
    end
    
    -- Main rounds
    for round = 9, 1, -1 do
        aes_core.inv_shift_rows(state)
        aes_core.inv_sub_bytes(state)
        for i = 1, 16 do
            state[i] = aes_core.bxor(state[i], round_keys[round * 16 + i])
        end
        aes_core.inv_mix_columns(state)
    end
    
    -- Final round
    aes_core.inv_shift_rows(state)
    aes_core.inv_sub_bytes(state)
    for i = 1, 16 do
        state[i] = aes_core.bxor(state[i], round_keys[i])
    end
    
    return aes_core.state_to_bytes(state)
end

return aes