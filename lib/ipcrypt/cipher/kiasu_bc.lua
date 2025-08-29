-- kiasu_bc.lua - KIASU-BC tweakable block cipher implementation using shared AES core

local utils = require("ipcrypt.utils")
local aes_core = require("ipcrypt.cipher.aes_core")

local kiasu_bc = {}

-- Pad an 8-byte tweak to 16 bytes for KIASU-BC
-- Places each 2-byte pair at the start of each 4-byte group
function kiasu_bc.pad_tweak(tweak)
    assert(#tweak == 8, "Tweak must be 8 bytes")
    
    local padded = {}
    for i = 0, 3 do
        padded[i * 4 + 1] = string.byte(tweak, i * 2 + 1)
        padded[i * 4 + 2] = string.byte(tweak, i * 2 + 2)
        padded[i * 4 + 3] = 0
        padded[i * 4 + 4] = 0
    end
    
    local result = {}
    for i = 1, 16 do
        result[i] = string.char(padded[i])
    end
    
    return table.concat(result)
end

-- KIASU-BC encryption
function kiasu_bc.encrypt(key, tweak, plaintext)
    assert(#key == 16, "Key must be 16 bytes")
    assert(#tweak == 8, "Tweak must be 8 bytes")
    assert(#plaintext == 16, "Plaintext must be 16 bytes")
    
    local round_keys = aes_core.expand_key(key)
    local padded_tweak = kiasu_bc.pad_tweak(tweak)
    local padded_tweak_state = aes_core.bytes_to_state(padded_tweak)
    
    -- Initial state
    local state = aes_core.bytes_to_state(plaintext)
    
    -- Initial AddRoundKey with tweak
    for i = 1, 16 do
        state[i] = aes_core.bxor(aes_core.bxor(state[i], round_keys[i]), padded_tweak_state[i])
    end
    
    -- Main rounds
    for round = 1, 9 do
        aes_core.sub_bytes(state)
        state = aes_core.shift_rows_row_major(state)
        aes_core.mix_columns(state)
        
        for i = 1, 16 do
            state[i] = aes_core.bxor(aes_core.bxor(state[i], round_keys[round * 16 + i]), padded_tweak_state[i])
        end
    end
    
    -- Final round
    aes_core.sub_bytes(state)
    state = aes_core.shift_rows_row_major(state)
    
    for i = 1, 16 do
        state[i] = aes_core.bxor(aes_core.bxor(state[i], round_keys[160 + i]), padded_tweak_state[i])
    end
    
    return aes_core.state_to_bytes(state)
end

-- KIASU-BC decryption
function kiasu_bc.decrypt(key, tweak, ciphertext)
    assert(#key == 16, "Key must be 16 bytes")
    assert(#tweak == 8, "Tweak must be 8 bytes")
    assert(#ciphertext == 16, "Ciphertext must be 16 bytes")
    
    local round_keys = aes_core.expand_key(key)
    local padded_tweak = kiasu_bc.pad_tweak(tweak)
    local padded_tweak_state = aes_core.bytes_to_state(padded_tweak)
    
    -- Initial state
    local state = aes_core.bytes_to_state(ciphertext)
    
    -- Initial AddRoundKey with tweak
    for i = 1, 16 do
        state[i] = aes_core.bxor(aes_core.bxor(state[i], round_keys[160 + i]), padded_tweak_state[i])
    end
    
    state = aes_core.inv_shift_rows_row_major(state)
    aes_core.inv_sub_bytes(state)
    
    -- Main rounds
    for round = 9, 1, -1 do
        for i = 1, 16 do
            state[i] = aes_core.bxor(aes_core.bxor(state[i], round_keys[round * 16 + i]), padded_tweak_state[i])
        end
        
        aes_core.inv_mix_columns(state)
        state = aes_core.inv_shift_rows_row_major(state)
        aes_core.inv_sub_bytes(state)
    end
    
    -- Final round
    for i = 1, 16 do
        state[i] = aes_core.bxor(aes_core.bxor(state[i], round_keys[i]), padded_tweak_state[i])
    end
    
    return aes_core.state_to_bytes(state)
end

return kiasu_bc