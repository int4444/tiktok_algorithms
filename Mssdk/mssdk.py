import base64
import binascii
import json
import random
import secrets
import time
import uuid
import zlib
from typing import Union

from google.protobuf.json_format import MessageToJson, MessageToDict

from .chipher.aes_chipher import AESCipher
from .chipher.xtea_chipher import XteaCipher
from .data.chipher import AESConfig, XteaConfig

from .proto import mssdk_pb2


class MSSDK(object):

    def __init__(
            self,
            aes: AESConfig,
            xtea: XteaConfig
    ):
        self.aes_config = aes
        self.xtea_config = xtea

        self._xtea_cipher = XteaCipher(self.xtea_config.key, self.xtea_config.iv)
        self._aes_cipher = AESCipher(self.aes_config.key, self.aes_config.iv)

    def encode(self, raw):
        return self._aes_cipher.encrypt(self._xtea_cipher.encrypt(raw))

    def decode(self, message: bytes, get_seed: bool = False) -> bytes:
        if get_seed:
            aes_decoded = AESCipher(key=self.aes_config.key, iv=self.aes_config.iv).decrypt(message)
            return XteaCipher(key=self.xtea_config.key, iv=self.xtea_config.iv).decrypt(aes_decoded)

        aes_decoded = AESCipher(key=self.aes_config.key, iv=self.aes_config.iv).decrypt(message)
        return XteaCipher(key=self.xtea_config.key, iv=self.xtea_config.iv).decrypt(aes_decoded)

    def decode_response(
            self,
            buffer: str,
            request: str = "report"
    ):
        message = mssdk_pb2.MssdkResponse()

        payload = base64.b64decode(buffer).hex()
        message.ParseFromString(bytes.fromhex(payload))

        decoded = self.decode(message.body)
        decompressed = zlib.decompress(decoded)

        message.body = decompressed

        if request == "token":
            token_response = mssdk_pb2.TokenBody()
            token_response.ParseFromString(bytes.fromhex(message.body.hex()))
            result = MessageToDict(token_response)

            response = dict()
            response["token"] = result.get("token")
            return response

        if request == "common_setting":
            common_setting_response = mssdk_pb2.TokenBody()
            common_setting_response.ParseFromString(bytes.fromhex(message.body.hex()))
            result = MessageToDict(common_setting_response)
            return dict(result)

        if request == "report":
            return MessageToJson(message)

        if request == "seed":
            seed_response = mssdk_pb2.GetSeedResponsePayload()
            seed_response.ParseFromString(bytes.fromhex(message.body.hex()))


            algo = int.from_bytes(seed_response.u2.u1.encode(), byteorder="big") >> 1
            result = MessageToDict(seed_response)

            response = dict()
            response["seed"] = result.get("secDeviceId")
            response["algorithm"] = algo

            return response

    def prepare_message(self, protobuf):
        second_random_bytes = secrets.token_bytes(4)

        zlib_with_padding = len(protobuf).to_bytes(4, byteorder='little') + zlib.compress(protobuf, level=1)

        buffer = bytearray()
        align_size = (-(len(zlib_with_padding)) & 0x7)
        pad_len = ((align_size + 0x7) & 0x3)
        zero_padding_size = (align_size + 7) - pad_len

        pad_bytes = int.from_bytes(second_random_bytes, byteorder='big')
        buffer.append((pad_bytes & 0xF8) | (align_size & 0xFF))

        pad_bytes = pad_bytes >> 0x8
        for i in range(pad_len):
            buffer.append(pad_bytes & 0xff)
            pad_bytes = pad_bytes >> 0x8

        if pad_len >= 2:
            crc_sum = self.crc16(bytes(zlib_with_padding)).to_bytes(2, byteorder='big')
            buffer[1] = crc_sum[0]
            buffer[2] = crc_sum[1]
            buffer += zlib_with_padding
            buffer += b'\x00' * zero_padding_size
        else:
            buffer += zlib_with_padding
            buffer += self.crc16(bytes(zlib_with_padding)).to_bytes(2, byteorder='big')
            buffer += b'\x00' * (zero_padding_size - 2)

        return buffer

    @staticmethod
    def crc16(data: bytes, polynomial: int = 0x1021, initial_crc: int = 0xFFFF) -> int:
        crc = initial_crc
        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ polynomial
                else:
                    crc <<= 1
                crc &= 0xFFFF  # Ensure CRC is 16-bit
        return crc

    @staticmethod
    def prepare_get_token_message(protobuf):
        second_random_bytes = bytes.fromhex('402a2150')
        zlib_with_padding = bytes.fromhex('030000') + zlib.compress(protobuf)

        buffer = bytearray()
        padded_zlib_result_len = len(zlib_with_padding)
        uxtb_from_len = ((0 - padded_zlib_result_len) & 0x7)

        pad_len = (uxtb_from_len + 0x7) & 0x3
        buffer.append(second_random_bytes[3] + pad_len)
        pad_bytes = int.from_bytes(second_random_bytes, byteorder='big')
        if pad_len == 0:
            buffer += pad_bytes.to_bytes(4, byteorder='little')
        else:
            for i in range(pad_len):
                buffer.append(pad_bytes & 0xff)
                pad_bytes = pad_bytes >> 0x8

        buffer += zlib_with_padding

        return buffer

    @staticmethod
    def prepare_report_message(protobuf):
        second_random_bytes = bytes.fromhex('402a2150')
        zlib_with_padding = bytes.fromhex('060000') + zlib.compress(protobuf)

        buffer = bytearray()
        padded_zlib_result_len = len(zlib_with_padding)
        uxtb_from_len = ((0 - padded_zlib_result_len) & 0x7)

        pad_len = (uxtb_from_len + 0x7) & 0x3
        buffer.append(second_random_bytes[3] + pad_len)
        pad_bytes = int.from_bytes(second_random_bytes, byteorder='big')
        if pad_len == 0:
            buffer += pad_bytes.to_bytes(4, byteorder='little')
        else:
            for i in range(pad_len):
                buffer.append(pad_bytes & 0xff)
                pad_bytes = pad_bytes >> 0x8

        buffer += zlib_with_padding

        return buffer
