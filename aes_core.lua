-- aes_core.lua - Shared AES core operations

local aes_core = {}

-- Use bit32 library if available, otherwise use Lua 5.3+ bitwise operators
local band, bor, bxor, lshift, rshift
if bit32 then
    band = bit32.band
    bor = bit32.bor
    bxor = bit32.bxor
    lshift = function(x, n) return bit32.lshift(x, n) % 0x100000000 end
    rshift = bit32.rshift
else
    -- Lua 5.3+ bitwise operators
    band = function(a, b) return a & b end
    bor = function(a, b) return a | b end
    bxor = function(a, b) return a ~ b end
    lshift = function(x, n) return (x << n) & 0xFFFFFFFF end
    rshift = function(x, n) return x >> n end
end

-- Export bit operations for use by other modules
aes_core.band = band
aes_core.bor = bor
aes_core.bxor = bxor
aes_core.lshift = lshift
aes_core.rshift = rshift

-- AES S-box
aes_core.SBOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
}

-- Inverse S-box
aes_core.INV_SBOX = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
}

-- Round constants
aes_core.RCON = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

-- GF(2^8) multiplication by 2
function aes_core.mul2(x)
    local result = lshift(x, 1)
    if band(x, 0x80) ~= 0 then
        result = bxor(result, 0x1B)
    end
    return band(result, 0xFF)
end

-- GF(2^8) multiplication by 3
function aes_core.mul3(x)
    return bxor(aes_core.mul2(x), x)
end

-- GF(2^8) multiplication
function aes_core.gmul(a, b)
    local p = 0
    for i = 0, 7 do
        if band(b, 1) ~= 0 then
            p = bxor(p, a)
        end
        local hi_bit_set = band(a, 0x80) ~= 0
        a = band(lshift(a, 1), 0xFF)
        if hi_bit_set then
            a = bxor(a, 0x1B)
        end
        b = rshift(b, 1)
    end
    return p
end

-- Convert state from bytes to matrix
function aes_core.bytes_to_state(bytes)
    local state = {}
    for i = 0, 15 do
        state[i + 1] = string.byte(bytes, i + 1)
    end
    return state
end

-- Convert state from matrix to bytes
function aes_core.state_to_bytes(state)
    local bytes = {}
    for i = 1, 16 do
        bytes[i] = string.char(state[i])
    end
    return table.concat(bytes)
end

-- SubBytes transformation
function aes_core.sub_bytes(state)
    for i = 1, 16 do
        state[i] = aes_core.SBOX[state[i] + 1]
    end
    return state
end

-- Inverse SubBytes transformation
function aes_core.inv_sub_bytes(state)
    for i = 1, 16 do
        state[i] = aes_core.INV_SBOX[state[i] + 1]
    end
    return state
end

-- ShiftRows transformation for standard AES column-major ordering
function aes_core.shift_rows(state)
    local temp = state[2]
    state[2] = state[6]
    state[6] = state[10]
    state[10] = state[14]
    state[14] = temp
    
    temp = state[3]
    state[3] = state[11]
    state[11] = temp
    temp = state[7]
    state[7] = state[15]
    state[15] = temp
    
    temp = state[4]
    state[4] = state[16]
    state[16] = state[12]
    state[12] = state[8]
    state[8] = temp
    
    return state
end

-- ShiftRows for row-major ordering (used by KIASU-BC)
function aes_core.shift_rows_row_major(state)
    local new_state = {}
    new_state[1] = state[1]
    new_state[2] = state[6]
    new_state[3] = state[11]
    new_state[4] = state[16]
    new_state[5] = state[5]
    new_state[6] = state[10]
    new_state[7] = state[15]
    new_state[8] = state[4]
    new_state[9] = state[9]
    new_state[10] = state[14]
    new_state[11] = state[3]
    new_state[12] = state[8]
    new_state[13] = state[13]
    new_state[14] = state[2]
    new_state[15] = state[7]
    new_state[16] = state[12]
    return new_state
end

-- Inverse ShiftRows for standard AES
function aes_core.inv_shift_rows(state)
    local temp = state[14]
    state[14] = state[10]
    state[10] = state[6]
    state[6] = state[2]
    state[2] = temp
    
    temp = state[3]
    state[3] = state[11]
    state[11] = temp
    temp = state[7]
    state[7] = state[15]
    state[15] = temp
    
    temp = state[8]
    state[8] = state[12]
    state[12] = state[16]
    state[16] = state[4]
    state[4] = temp
    
    return state
end

-- Inverse ShiftRows for row-major ordering (used by KIASU-BC)
function aes_core.inv_shift_rows_row_major(state)
    local new_state = {}
    new_state[1] = state[1]
    new_state[2] = state[14]
    new_state[3] = state[11]
    new_state[4] = state[8]
    new_state[5] = state[5]
    new_state[6] = state[2]
    new_state[7] = state[15]
    new_state[8] = state[12]
    new_state[9] = state[9]
    new_state[10] = state[6]
    new_state[11] = state[3]
    new_state[12] = state[16]
    new_state[13] = state[13]
    new_state[14] = state[10]
    new_state[15] = state[7]
    new_state[16] = state[4]
    return new_state
end

-- MixColumns transformation
function aes_core.mix_columns(state)
    for c = 0, 3 do
        local i = c * 4 + 1
        local s0 = state[i]
        local s1 = state[i + 1]
        local s2 = state[i + 2]
        local s3 = state[i + 3]
        
        state[i] = bxor(bxor(bxor(aes_core.mul2(s0), aes_core.mul3(s1)), s2), s3)
        state[i + 1] = bxor(bxor(bxor(s0, aes_core.mul2(s1)), aes_core.mul3(s2)), s3)
        state[i + 2] = bxor(bxor(bxor(s0, s1), aes_core.mul2(s2)), aes_core.mul3(s3))
        state[i + 3] = bxor(bxor(bxor(aes_core.mul3(s0), s1), s2), aes_core.mul2(s3))
    end
    return state
end

-- Inverse MixColumns transformation
function aes_core.inv_mix_columns(state)
    for c = 0, 3 do
        local i = c * 4 + 1
        local s0 = state[i]
        local s1 = state[i + 1]
        local s2 = state[i + 2]
        local s3 = state[i + 3]
        
        state[i] = bxor(bxor(bxor(aes_core.gmul(0x0e, s0), aes_core.gmul(0x0b, s1)), 
                            aes_core.gmul(0x0d, s2)), aes_core.gmul(0x09, s3))
        state[i + 1] = bxor(bxor(bxor(aes_core.gmul(0x09, s0), aes_core.gmul(0x0e, s1)), 
                               aes_core.gmul(0x0b, s2)), aes_core.gmul(0x0d, s3))
        state[i + 2] = bxor(bxor(bxor(aes_core.gmul(0x0d, s0), aes_core.gmul(0x09, s1)), 
                               aes_core.gmul(0x0e, s2)), aes_core.gmul(0x0b, s3))
        state[i + 3] = bxor(bxor(bxor(aes_core.gmul(0x0b, s0), aes_core.gmul(0x0d, s1)), 
                               aes_core.gmul(0x09, s2)), aes_core.gmul(0x0e, s3))
    end
    return state
end

-- AddRoundKey transformation
function aes_core.add_round_key(state, round_key)
    for i = 1, 16 do
        state[i] = bxor(state[i], round_key[i])
    end
    return state
end

-- Rotate word for key expansion
function aes_core.rot_word(word)
    return {word[2], word[3], word[4], word[1]}
end

-- Key expansion for AES-128
function aes_core.expand_key(key)
    assert(#key == 16, "Key must be 16 bytes")
    
    local round_keys = {}
    local key_state = aes_core.bytes_to_state(key)
    
    -- First round key is the key itself
    for i = 1, 16 do
        round_keys[i] = key_state[i]
    end
    
    -- Generate 10 more round keys
    for round = 1, 10 do
        -- Rotate word
        local temp = {
            round_keys[(round - 1) * 16 + 14],
            round_keys[(round - 1) * 16 + 15],
            round_keys[(round - 1) * 16 + 16],
            round_keys[(round - 1) * 16 + 13]
        }
        
        -- SubBytes
        for i = 1, 4 do
            temp[i] = aes_core.SBOX[temp[i] + 1]
        end
        
        -- XOR with round constant
        temp[1] = bxor(temp[1], aes_core.RCON[round])
        
        -- Generate round key
        for i = 0, 3 do
            for j = 0, 3 do
                local idx = round * 16 + i * 4 + j + 1
                if i == 0 then
                    round_keys[idx] = bxor(round_keys[(round - 1) * 16 + j + 1], temp[j + 1])
                else
                    round_keys[idx] = bxor(round_keys[(round - 1) * 16 + i * 4 + j + 1],
                                          round_keys[round * 16 + (i - 1) * 4 + j + 1])
                end
            end
        end
    end
    
    return round_keys
end

-- Get round keys as byte strings (for KIASU-BC)
function aes_core.get_round_key_bytes(expanded_keys, round)
    local start_idx = (round - 1) * 16 + 1
    local key_bytes = {}
    for i = 0, 15 do
        key_bytes[i + 1] = string.char(expanded_keys[start_idx + i])
    end
    return table.concat(key_bytes)
end

return aes_core