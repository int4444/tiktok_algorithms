from Crypto.Cipher import AES


class AESCipher(object):

    def __init__(self, key: str = 'b8d72ddec05142948bbf2dc81d63759c', iv: str = 'd6c3969582f9ac5313d39c180b54a2bc'):
        self.bs = AES.block_size
        self.key = bytes.fromhex(key)
        self.iv = bytes.fromhex(iv)


    def encrypt(self, raw: bytes) -> bytes:
        raw = self._pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        result = cipher.encrypt(bytes(raw))
        return result

    def decrypt(self, enc: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        result = self._unpad(cipher.decrypt(enc))

        return result

    @staticmethod
    def _pad(s: bytes) -> bytes:
        fill_number = 16 - (len(s) % 16)
        for i in range(fill_number):
            s += fill_number.to_bytes(1, byteorder='big')

        return s

    @staticmethod
    def _unpad(s: bytes) -> bytes:
        return s[:-ord(s[len(s) - 1:])]