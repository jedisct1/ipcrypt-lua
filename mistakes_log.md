# IPCrypt Lua Implementation - Mistakes Log

This log tracks errors and lessons learned during the implementation of IPCrypt in pure Lua.

## Date: 2025-08-28

### Implementation Notes:
- Starting implementation based on Python reference
- Need to implement AES from scratch as Lua has no built-in crypto
- Must handle byte operations carefully as Lua uses numbers differently than Python

### Code Redundancy Issue Identified:
**Mistake:** Initially created separate implementations of AES operations in both `aes.lua` and `kiasu_bc.lua`, resulting in significant code duplication. Both modules had identical implementations of:
- S-box and inverse S-box tables
- Round constants
- GF(2^8) multiplication functions
- State conversion functions
- SubBytes/InvSubBytes transformations
- MixColumns/InvMixColumns transformations
- Key expansion algorithm

**Solution:** Created `aes_core.lua` module to share common AES operations between implementations. This:
- Reduced code size by ~40% (eliminated ~300 lines of duplicate code)
- Made maintenance easier - single source of truth for AES operations
- Improved code organization and readability
- Note: KIASU-BC uses row-major ordering for ShiftRows while standard AES uses column-major, so both variants are provided in the core module

**Lesson Learned:** When implementing related cryptographic algorithms, identify shared operations early and create a common module to avoid redundancy.

---