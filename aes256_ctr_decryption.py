# AES-256 Encryption in CTR Mode (Manual Implementation)
# Encryption module implementing AES-256 in CTR mode
# 
# - Algorithm: AES (Advanced Encryption Standard)
# - Mode: CTR (Counter Mode) using 12-byte nonce + 4-byte counter
# - Key Size: 256 bits (32 bytes)
# - Padding: None (uses zero-padding for partial blocks)
# - Block Size: 16 bytes
# - Encoding: Base64 for ciphertext output
# - Charset: UTF-8 for plaintext input/output
# - Implementation: Fully manual in Python (no external crypto libs)
# - Symmetric: Same function used for encryption and decryption

import base64

s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

rcon = [
    0x00,0x01,0x02,0x04,0x08,
    0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a
]

def add_round_key(state, round_key):
    return [b ^ rk for b, rk in zip(state, round_key)]

def sub_bytes(state):
    return [s_box[b] for b in state]

def shift_rows(state):
    return [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def mix_columns(state):
    for i in range(4):
        s0 = gmul(2, state[4*i]) ^ gmul(3, state[4*i+1]) ^ state[4*i+2] ^ state[4*i+3]
        s1 = state[4*i] ^ gmul(2, state[4*i+1]) ^ gmul(3, state[4*i+2]) ^ state[4*i+3]
        s2 = state[4*i] ^ state[4*i+1] ^ gmul(2, state[4*i+2]) ^ gmul(3, state[4*i+3])
        s3 = gmul(3, state[4*i]) ^ state[4*i+1] ^ state[4*i+2] ^ gmul(2, state[4*i+3])
        state[4*i], state[4*i+1], state[4*i+2], state[4*i+3] = s0, s1, s2, s3

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [s_box[b] for b in word]

def key_expansion(key):
    assert len(key) == 32
    nk, nb, nr = 8, 4, 14
    w = list(key)
    i = nk
    while len(w) < nb * (nr + 1) * 4:
        temp = w[-4:]
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w += [w[-nk*4 + j] ^ temp[j] for j in range(4)]
        i += 1
    return w

def aes_encrypt_block(plaintext, round_keys, rounds=14):
    state = list(plaintext)
    state = add_round_key(state, round_keys[:16])
    for r in range(1, rounds):
        state = sub_bytes(state)
        state = shift_rows(state)
        mix_columns(state)
        state = add_round_key(state, round_keys[r*16:(r+1)*16])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[rounds*16:(rounds+1)*16])
    return bytes(state)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def increment_counter(counter):
    val = int.from_bytes(counter, 'big') + 1
    return val.to_bytes(len(counter), 'big')

def aes_ctr_decrypt(ciphertext, key, nonce):
    assert len(nonce) == 12
    round_keys = key_expansion(key)
    block_size = 16
    output = b""
    counter = nonce + b'\x00\x00\x00\x00'
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        encrypted_counter = aes_encrypt_block(counter, round_keys)
        output_block = xor_bytes(block.ljust(block_size, b'\x00'), encrypted_counter)
        output += output_block[:len(block)]
        counter = increment_counter(counter)
    return output


if __name__ == "__main__":
    key = b"1234567890abcdef1234567890abcdef"
    nonce = b"123456789012"
    ciphertext_b64 = "3KlmUby7UIJeez/HJiLu2GlP+ZHq+tlmGRMgfxvoPMOLiVpMO1OiNKN3pRKkVpV1y78IE+3n1OliFP/2tg=="
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aes_ctr_decrypt(ciphertext, key, nonce)
    print("Decrypted:", plaintext.decode())
