import socket
import argparse
import math
from colorline import cprint
from pprint import pprint
from functools import partial
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util import Padding

colorprint = partial(cprint, color='r', bcolor='k')

class BytesOperation:
    @staticmethod
    def str_rev(obj_str):
        return ''.join([obj_str[x:x+2] for x in range(len(obj_str))][-2::-2])

class DeviceInfoOp(BytesOperation):
    def __init__(self):
        pass

    @staticmethod
    def form_FHDR(DevAddr, FCtrl, FCnt, FOpts=None):
        DevAddr = DeviceInfoOp.str_rev(DevAddr)
        FCnt = DeviceInfoOp.str_rev(FCnt)
        return '{}{}{}'.format(DevAddr, FCtrl, FCnt)

    @staticmethod
    def _base_block(**kwargs):
        kwargs['DevAddr'] = DeviceInfoOp.str_rev(kwargs.get('DevAddr'))
        kwargs['FCnt'] = DeviceInfoOp.str_rev(kwargs.get('FCnt'))
        return '00000000{direction}{DevAddr}{FCnt}00'.format(**kwargs)

    @staticmethod
    def _B0(**kwargs):
        base_block = DeviceInfoOp._base_block(**kwargs)
        return '49{base_block}{msg_length}'.format(base_block=base_block, msg_length=kwargs.get('msg_length'))

    @staticmethod
    def _A(**kwargs):
        base_block = DeviceInfoOp._base_block(**kwargs)
        return '01{base_block}{i}'.format(base_block=base_block, i=kwargs.get('i'))

    @staticmethod
    def cal_mic(key, payload, direction, **kwargs):
        payload = payload.encode().hex()
        msg = '{MHDR}{FHDR}{FPort}{payload}'.format(payload=payload, **kwargs)
        msg_bytes = msg.encode()
        msg_length = '{:0>2x}'.format(len(msg_bytes)//2)
        B0 = DeviceInfoOp._B0(direction=direction, msg_length=msg_length, **kwargs)
        obj_msg = B0 + msg
        obj_msg = bytearray.fromhex(obj_msg)
        cobj = CMAC.new(key, ciphermod=AES)
        cobj.update(obj_msg)
        return cobj.hexdigest()

    @staticmethod
    def encrypt(key, payload, **kwargs):
        payload = payload.encode()
        pld_len = len(payload) // 2
        payload = Padding.pad(payload, 16)
        k = math.ceil(pld_len / 16)
        iv = b''
        cryptor = AES.new(key, AES.MODE_ECB)
        S = b''
        for i in range(1, k + 1):
            kwargs['i'] = '{:0>2x}'.format(i)
            _A_each = DeviceInfoOp._A(**kwargs)
            Ai = bytearray.fromhex(_A_each)
            Si = cryptor.encrypt(Ai)
            S += Si
        return b''.join([bytearray.fromhex('{:0>2x}'.format(x ^ y)) for (x, y) in zip(S, payload)])[:pld_len * 2 + 1]

if __name__ == '__main__':
    DevAddr = 'ABCDEF12'
    direction = '00'
    FCnt = '000000FF'
    FCnt_low = FCnt[-4:]
    payload = 'hello'
    FPort = '02'
    MHDR = '80'
    FCtrl = '00'
    key = bytearray.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    device = DeviceInfoOp()
    FHDR = device.form_FHDR(DevAddr=DevAddr, FCtrl=FCtrl, FCnt=FCnt_low)
    kwargs = {
        'DevAddr': DevAddr,
        'FCnt': FCnt,
        'FHDR': FHDR,
        'MHDR': MHDR,
        'FPort': FPort,
        'direction': direction,
    }
    mic = device.cal_mic(key=key, payload=payload, direction=direction, DevAddr=DevAddr, FCnt=FCnt, FHDR=FHDR, MHDR=MHDR, FPort=FPort)
    enc_msg = device.encrypt(key=key, payload=payload, **kwargs)

