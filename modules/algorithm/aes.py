# CryptoChat/modules/algorithm/aes.py
import os
import secrets
from typing import List, Tuple


class AES:
    """AES-128/192/256 implementation in CBC mode with PKCS#7 padding"""
    
    # S-Box and inverse S-Box tables
    _S_BOX = [
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
    ]

    _INV_S_BOX = [
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
    ]

    # Rcon table for key expansion
    _RCON = [
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
    ]

    def __init__(self, key: bytes, iv: bytes = None):
        """Initialize AES cipher with key and IV (for CBC mode)"""
        self.key = key
        self.iv = iv or os.urandom(16)  # 16-byte IV for CBC mode
        self.Nk = len(key) // 4  # Key length in 32-bit words (4/6/8 for 128/192/256)
        self.Nr = {4: 10, 6: 12, 8: 14}[self.Nk]  # Rounds based on key size
        self.w = self._key_expansion()

    def _sub_word(self, word: int) -> int:
        """Apply S-Box substitution to a 32-bit word"""
        return (self._S_BOX[(word >> 24) & 0xff] << 24 |
                self._S_BOX[(word >> 16) & 0xff] << 16 |
                self._S_BOX[(word >> 8) & 0xff] << 8 |
                self._S_BOX[word & 0xff])

    def _rot_word(self, word: int) -> int:
        """Rotate 32-bit word left by 8 bits"""
        return ((word << 8) & 0xffffffff) | ((word >> 24) & 0xff)

    def _key_expansion(self) -> List[int]:
        """Expand key into round keys"""
        w = [0] * (self.Nr + 1) * 4
        for i in range(self.Nk):
            w[i] = (self.key[4*i] << 24) | (self.key[4*i+1] << 16) | (self.key[4*i+2] << 8) | self.key[4*i+3]

        for i in range(self.Nk, (self.Nr + 1) * 4):
            temp = w[i-1]
            if i % self.Nk == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ self._RCON[i // self.Nk]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self._sub_word(temp)
            w[i] = w[i - self.Nk] ^ temp
        return w

    def _add_round_key(self, state: List[int], round: int) -> None:
        """XOR state with round key"""
        for i in range(4):
            state[i] ^= self.w[round*4 + i]

    def _sub_bytes(self, state: List[int]) -> None:
        """Apply S-Box substitution to each byte"""
        for i in range(4):
            state[i] = self._sub_word(state[i])

    def _inv_sub_bytes(self, state: List[int]) -> None:
        """Apply inverse S-Box substitution to each byte"""
        for i in range(4):
            word = state[i]
            inv_word = (self._INV_S_BOX[(word >> 24) & 0xff] << 24 |
                       self._INV_S_BOX[(word >> 16) & 0xff] << 16 |
                       self._INV_S_BOX[(word >> 8) & 0xff] << 8 |
                       self._INV_S_BOX[word & 0xff])
            state[i] = inv_word

    def _shift_rows(self, state: List[int]) -> None:
        """Shift rows of state matrix"""
        # Row 1: shift left by 1
        state[1] = ((state[1] << 8) & 0xffffffff) | ((state[1] >> 24) & 0xff)
        # Row 2: shift left by 2
        state[2] = ((state[2] << 16) & 0xffffffff) | ((state[2] >> 16) & 0xffff)
        # Row 3: shift left by 3
        state[3] = ((state[3] << 24) & 0xffffffff) | ((state[3] >> 8) & 0xff000000)

    def _inv_shift_rows(self, state: List[int]) -> None:
        """Inverse shift rows of state matrix"""
        # Row 1: shift right by 1
        state[1] = ((state[1] >> 8) & 0xffffffff) | ((state[1] << 24) & 0xff000000)
        # Row 2: shift right by 2
        state[2] = ((state[2] >> 16) & 0xffffffff) | ((state[2] << 16) & 0xffff0000)
        # Row 3: shift right by 3
        state[3] = ((state[3] >> 24) & 0xffffffff) | ((state[3] << 8) & 0xffffffff)

    def _mix_columns(self, state: List[int]) -> None:
        """Mix columns using fixed matrix multiplication"""
        for i in range(4):
            word = state[i]
            a = (word >> 24) & 0xff
            b = (word >> 16) & 0xff
            c = (word >> 8) & 0xff
            d = word & 0xff

            state[i] = (
                (self._gf_mult(a, 2) ^ self._gf_mult(b, 3) ^ c ^ d) << 24 |
                (a ^ self._gf_mult(b, 2) ^ self._gf_mult(c, 3) ^ d) << 16 |
                (a ^ b ^ self._gf_mult(c, 2) ^ self._gf_mult(d, 3)) << 8 |
                (self._gf_mult(a, 3) ^ b ^ c ^ self._gf_mult(d, 2))
            )

    def _inv_mix_columns(self, state: List[int]) -> None:
        """Inverse mix columns using fixed matrix multiplication"""
        for i in range(4):
            word = state[i]
            a = (word >> 24) & 0xff
            b = (word >> 16) & 0xff
            c = (word >> 8) & 0xff
            d = word & 0xff

            state[i] = (
                (self._gf_mult(a, 0x0e) ^ self._gf_mult(b, 0x0b) ^ self._gf_mult(c, 0x0d) ^ self._gf_mult(d, 0x09)) << 24 |
                (self._gf_mult(a, 0x09) ^ self._gf_mult(b, 0x0e) ^ self._gf_mult(c, 0x0b) ^ self._gf_mult(d, 0x0d)) << 16 |
                (self._gf_mult(a, 0x0d) ^ self._gf_mult(b, 0x09) ^ self._gf_mult(c, 0x0e) ^ self._gf_mult(d, 0x0b)) << 8 |
                (self._gf_mult(a, 0x0b) ^ self._gf_mult(b, 0x0d) ^ self._gf_mult(c, 0x09) ^ self._gf_mult(d, 0x0e))
            )

    @staticmethod
    def _gf_mult(a: int, b: int) -> int:
        """Multiply two bytes in GF(2^8) with irreducible polynomial 0x11b"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit:
                a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p & 0xff

    def _cipher(self, state: List[int]) -> None:
        """AES encryption round function"""
        self._add_round_key(state, 0)
        for round in range(1, self.Nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, round)
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.Nr)

    def _inv_cipher(self, state: List[int]) -> None:
        """AES decryption round function"""
        self._add_round_key(state, self.Nr)
        for round in range(self.Nr - 1, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, round)
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, 0)

    @staticmethod
    def pad(data: bytes) -> bytes:
        """PKCS#7 padding"""
        pad_length = 16 - (len(data) % 16)
        return data + bytes([pad_length]) * pad_length

    @staticmethod
    def unpad(data: bytes) -> bytes:
        """Remove PKCS#7 padding"""
        pad_length = data[-1]
        return data[:-pad_length]

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data in CBC mode"""
        data = self.pad(data)
        ciphertext = b''
        prev_block = self.iv

        for i in range(0, len(data), 16):
            block = data[i:i+16]
            # XOR with previous block (IV for first block)
            xor_block = bytes(a ^ b for a, b in zip(block, prev_block))
            
            # Convert to state matrix (4x4 words)
            state = [
                (xor_block[0] << 24) | (xor_block[4] << 16) | (xor_block[8] << 8) | xor_block[12],
                (xor_block[1] << 24) | (xor_block[5] << 16) | (xor_block[9] << 8) | xor_block[13],
                (xor_block[2] << 24) | (xor_block[6] << 16) | (xor_block[10] << 8) | xor_block[14],
                (xor_block[3] << 24) | (xor_block[7] << 16) | (xor_block[11] << 8) | xor_block[15]
            ]

            self._cipher(state)

            # Convert back to bytes
            encrypted_block = (
                bytes([(state[0] >> 24) & 0xff, (state[1] >> 24) & 0xff, (state[2] >> 24) & 0xff, (state[3] >> 24) & 0xff,
                       (state[0] >> 16) & 0xff, (state[1] >> 16) & 0xff, (state[2] >> 16) & 0xff, (state[3] >> 16) & 0xff,
                       (state[0] >> 8) & 0xff,  (state[1] >> 8) & 0xff,  (state[2] >> 8) & 0xff,  (state[3] >> 8) & 0xff,
                       state[0] & 0xff,          state[1] & 0xff,          state[2] & 0xff,          state[3] & 0xff])
            )

            ciphertext += encrypted_block
            prev_block = encrypted_block

        return ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data in CBC mode"""
        plaintext = b''
        prev_block = self.iv

        for i in range(0, len(data), 16):
            block = data[i:i+16]
            
            # Convert to state matrix (4x4 words)
            state = [
                (block[0] << 24) | (block[4] << 16) | (block[8] << 8) | block[12],
                (block[1] << 24) | (block[5] << 16) | (block[9] << 8) | block[13],
                (block[2] << 24) | (block[6] << 16) | (block[10] << 8) | block[14],
                (block[3] << 24) | (block[7] << 16) | (block[11] << 8) | block[15]
            ]

            self._inv_cipher(state)

            # Convert back to bytes
            decrypted_block = (
                bytes([(state[0] >> 24) & 0xff, (state[1] >> 24) & 0xff, (state[2] >> 24) & 0xff, (state[3] >> 24) & 0xff,
                       (state[0] >> 16) & 0xff, (state[1] >> 16) & 0xff, (state[2] >> 16) & 0xff, (state[3] >> 16) & 0xff,
                       (state[0] >> 8) & 0xff,  (state[1] >> 8) & 0xff,  (state[2] >> 8) & 0xff,  (state[3] >> 8) & 0xff,
                       state[0] & 0xff,          state[1] & 0xff,          state[2] & 0xff,          state[3] & 0xff])
            )

            # XOR with previous block (IV for first block)
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plaintext += plaintext_block
            prev_block = block

        return self.unpad(plaintext)
    

def generate_random_key(key_size: int = 16) -> bytes:
    return secrets.token_bytes(key_size)