local aes_core = {}

local str_byte, str_char = string.byte, string.char
local band = function(a, b) return a & b end
local bxor = function(a, b) return a ~ b end

aes_core.bxor = bxor

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

aes_core.RCON = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}
local function mul2(x)
    return band((x << 1) ~ ((x >> 7) * 0x1B), 0xFF)
end

local function mul3(x)
    return bxor(mul2(x), x)
end

local function mul4(x)
    local x2 = mul2(x)
    return mul2(x2)
end

local function mul8(x)
    local x2 = mul2(x)
    local x4 = mul2(x2)
    return mul2(x4)
end

local function mul9(x)
    return bxor(mul8(x), x)
end

local function mul11(x)
    local x2 = mul2(x)
    return bxor(bxor(mul8(x), x2), x)
end

local function mul13(x)
    local x4 = mul4(x)
    return bxor(bxor(mul8(x), x4), x)
end

local function mul14(x)
    local x2 = mul2(x)
    local x4 = mul2(x2)
    local x8 = mul2(x4)
    return bxor(bxor(x8, x4), x2)
end

function aes_core.bytes_to_state(bytes)
    return {str_byte(bytes, 1, 16)}
end

function aes_core.state_to_bytes(state)
    return str_char(state[1], state[2], state[3], state[4],
                    state[5], state[6], state[7], state[8],
                    state[9], state[10], state[11], state[12],
                    state[13], state[14], state[15], state[16])
end

function aes_core.sub_bytes(state)
    local SBOX = aes_core.SBOX
    state[1], state[2], state[3], state[4] =
        SBOX[state[1] + 1], SBOX[state[2] + 1], SBOX[state[3] + 1], SBOX[state[4] + 1]
    state[5], state[6], state[7], state[8] =
        SBOX[state[5] + 1], SBOX[state[6] + 1], SBOX[state[7] + 1], SBOX[state[8] + 1]
    state[9], state[10], state[11], state[12] =
        SBOX[state[9] + 1], SBOX[state[10] + 1], SBOX[state[11] + 1], SBOX[state[12] + 1]
    state[13], state[14], state[15], state[16] =
        SBOX[state[13] + 1], SBOX[state[14] + 1], SBOX[state[15] + 1], SBOX[state[16] + 1]
end

function aes_core.inv_sub_bytes(state)
    local INV_SBOX = aes_core.INV_SBOX
    state[1], state[2], state[3], state[4] =
        INV_SBOX[state[1] + 1], INV_SBOX[state[2] + 1], INV_SBOX[state[3] + 1], INV_SBOX[state[4] + 1]
    state[5], state[6], state[7], state[8] =
        INV_SBOX[state[5] + 1], INV_SBOX[state[6] + 1], INV_SBOX[state[7] + 1], INV_SBOX[state[8] + 1]
    state[9], state[10], state[11], state[12] =
        INV_SBOX[state[9] + 1], INV_SBOX[state[10] + 1], INV_SBOX[state[11] + 1], INV_SBOX[state[12] + 1]
    state[13], state[14], state[15], state[16] =
        INV_SBOX[state[13] + 1], INV_SBOX[state[14] + 1], INV_SBOX[state[15] + 1], INV_SBOX[state[16] + 1]
end

function aes_core.shift_rows(state)
    state[2], state[6], state[10], state[14] = state[6], state[10], state[14], state[2]
    state[3], state[7], state[11], state[15] = state[11], state[15], state[3], state[7]
    state[4], state[8], state[12], state[16] = state[16], state[4], state[8], state[12]
end

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

function aes_core.inv_shift_rows(state)
    state[2], state[6], state[10], state[14] = state[14], state[2], state[6], state[10]
    state[3], state[7], state[11], state[15] = state[11], state[15], state[3], state[7]
    state[4], state[8], state[12], state[16] = state[8], state[12], state[16], state[4]
end

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

function aes_core.mix_columns(state)
    for c = 0, 3 do
        local i = c * 4 + 1
        local s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        local t = bxor(bxor(s0, s1), bxor(s2, s3))

        state[i]     = bxor(bxor(s0, mul2(bxor(s0, s1))), t)
        state[i + 1] = bxor(bxor(s1, mul2(bxor(s1, s2))), t)
        state[i + 2] = bxor(bxor(s2, mul2(bxor(s2, s3))), t)
        state[i + 3] = bxor(bxor(s3, mul2(bxor(s3, s0))), t)
    end
end

function aes_core.inv_mix_columns(state)
    for c = 0, 3 do
        local i = c * 4 + 1
        local s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]

        state[i]     = bxor(bxor(mul14(s0), mul11(s1)), bxor(mul13(s2), mul9(s3)))
        state[i + 1] = bxor(bxor(mul9(s0), mul14(s1)), bxor(mul11(s2), mul13(s3)))
        state[i + 2] = bxor(bxor(mul13(s0), mul9(s1)), bxor(mul14(s2), mul11(s3)))
        state[i + 3] = bxor(bxor(mul11(s0), mul13(s1)), bxor(mul9(s2), mul14(s3)))
    end
end

function aes_core.expand_key(key)
    assert(#key == 16, "Key must be 16 bytes")

    local round_keys = {}
    local SBOX = aes_core.SBOX
    local RCON = aes_core.RCON

    local b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15,b16 = str_byte(key, 1, 16)
    round_keys[1], round_keys[2], round_keys[3], round_keys[4] = b1, b2, b3, b4
    round_keys[5], round_keys[6], round_keys[7], round_keys[8] = b5, b6, b7, b8
    round_keys[9], round_keys[10], round_keys[11], round_keys[12] = b9, b10, b11, b12
    round_keys[13], round_keys[14], round_keys[15], round_keys[16] = b13, b14, b15, b16

    for round = 1, 10 do
        local base = (round - 1) * 16
        local out  = round * 16

        local t0 = bxor(SBOX[round_keys[base + 14] + 1], RCON[round])
        local t1 = SBOX[round_keys[base + 15] + 1]
        local t2 = SBOX[round_keys[base + 16] + 1]
        local t3 = SBOX[round_keys[base + 13] + 1]
        round_keys[out + 1] = bxor(round_keys[base + 1], t0)
        round_keys[out + 2] = bxor(round_keys[base + 2], t1)
        round_keys[out + 3] = bxor(round_keys[base + 3], t2)
        round_keys[out + 4] = bxor(round_keys[base + 4], t3)

        round_keys[out + 5]  = bxor(round_keys[base + 5], round_keys[out + 1])
        round_keys[out + 6]  = bxor(round_keys[base + 6], round_keys[out + 2])
        round_keys[out + 7]  = bxor(round_keys[base + 7], round_keys[out + 3])
        round_keys[out + 8]  = bxor(round_keys[base + 8], round_keys[out + 4])

        round_keys[out + 9]  = bxor(round_keys[base + 9], round_keys[out + 5])
        round_keys[out + 10] = bxor(round_keys[base + 10], round_keys[out + 6])
        round_keys[out + 11] = bxor(round_keys[base + 11], round_keys[out + 7])
        round_keys[out + 12] = bxor(round_keys[base + 12], round_keys[out + 8])

        round_keys[out + 13] = bxor(round_keys[base + 13], round_keys[out + 9])
        round_keys[out + 14] = bxor(round_keys[base + 14], round_keys[out + 10])
        round_keys[out + 15] = bxor(round_keys[base + 15], round_keys[out + 11])
        round_keys[out + 16] = bxor(round_keys[base + 16], round_keys[out + 12])
    end

    return round_keys
end

function aes_core.get_round_key_bytes(expanded_keys, round)
    local start_idx = (round - 1) * 16 + 1
    return str_char(
        expanded_keys[start_idx + 0],  expanded_keys[start_idx + 1],
        expanded_keys[start_idx + 2],  expanded_keys[start_idx + 3],
        expanded_keys[start_idx + 4],  expanded_keys[start_idx + 5],
        expanded_keys[start_idx + 6],  expanded_keys[start_idx + 7],
        expanded_keys[start_idx + 8],  expanded_keys[start_idx + 9],
        expanded_keys[start_idx + 10], expanded_keys[start_idx + 11],
        expanded_keys[start_idx + 12], expanded_keys[start_idx + 13],
        expanded_keys[start_idx + 14], expanded_keys[start_idx + 15]
    )
end

return aes_core