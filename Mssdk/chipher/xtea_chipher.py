from random import randint

import xtea


class XteaCipher(object):

    def __init__(self, key: str = '782399bdfacedead3230313030343034', iv: str = '27042020'):
        self.key = bytes.fromhex(key)
        self.iv = bytes.fromhex(iv)
        self._first_encode_static_bytes = randint(0, 0x7fffffff).to_bytes(4, byteorder='big')

    def encrypt(self, raw: bytes) -> bytes:
        # random_bytes = randint(0x40000000, 0x4fffffff).to_bytes(4, byteorder='big')
        random_bytes = bytes.fromhex("78104c40")

        buffer = self._pad(bytearray(raw))

        rounds = self._get_xtea_rounds(random_bytes)
        xtea_random_bytes = bytearray(random_bytes)
        xtea_random_bytes.reverse()
        xtea_iv = b'' + xtea_random_bytes + self.iv
        result = xtea.new(self.key, mode=xtea.MODE_CBC, IV=xtea_iv, rounds=rounds).encrypt(bytes(buffer))

        enc_result = bytearray()
        enc_result.append(result[0] ^ 0x3)
        enc_result += result
        enc_result += xtea_random_bytes

        return bytes(enc_result)

    def decrypt(self, enc: bytes) -> bytes:
        random_bytes = bytearray(enc[len(enc) - 4:len(enc)])
        random_bytes.reverse()

        rounds = self._get_xtea_rounds(random_bytes)

        xtea_iv = b'' + enc[len(enc) - 4:len(enc)] + self.iv
        decode_result = xtea.new(self.key, mode=xtea.MODE_CBC, IV=xtea_iv, rounds=rounds).decrypt(enc[1:len(enc) - 4])

        decode_result = self._unpad(decode_result)
        zlib_part = decode_result[int(decode_result.hex().find('000078') / 2) + 2:]

        return bytes(zlib_part)

    @staticmethod
    def _get_xtea_rounds(random_bytes: bytes) -> int:
        int_random_bytes = int.from_bytes(random_bytes, byteorder='big')

        r3 = 0x1d
        r2 = XteaCipher.count_leading_zeroes(int_random_bytes)
        r2 = r3 - r2

        r1 = 0x5 << r2
        r3 = 0x1 << r2
        r0 = int_random_bytes

        r2 = 0
        while r0 != 0:
            if r1 == 0 and r1 == 0:
                break

            if r0 >= r1:
                r0 = r0 - r1
                r2 = r2 | r3

            if r0 >= (r1 >> 0x1):
                r0 = r0 - (r1 >> 0x1)
                r2 = r2 | (r3 >> 0x1)

            if r0 >= (r1 >> 0x2):
                r0 = r0 - (r1 >> 0x2)
                r2 = r2 | (r3 >> 0x2)

            if r0 >= (r1 >> 0x3):
                r0 = r0 - (r1 >> 0x3)
                r2 = r2 | (r3 >> 0x3)

            if r0 != 0x0:
                r3 = r3 >> 0x4
                r1 = r1 >> 0x4

        r3 = r2 * 0x5
        r1 = int_random_bytes - r3
        r0 = r1 << 0x3

        return (r0 + 0x20) * 2

    @staticmethod
    def count_leading_zeroes(value: int, max_bits: int = 32) -> int:
        value &= (1 << max_bits) - 1
        value <<= 1

        return max_bits - len(bin(value)) - 3

    def _pad(self, s: bytearray) -> bytearray:
        if len(s) % 16 != 0:
            fill_number = 16 - (len(s) % 16)
            for i in range(fill_number):
                s.append(0x0)

        return s

    @staticmethod
    def _unpad(s: bytearray) -> bytearray:
        pad_value = s[-1]
        while pad_value == 0x0:
            s = s[:len(s) - 1]
            pad_value = s[-1]

        return s