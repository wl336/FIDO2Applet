#!/usr/bin/env python

import argparse
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives import serialization

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate an attestation EC keypair')
    parser.add_argument('--curve', choices=['p256', 'p384', 'p521'], default='p256',
                        help='Elliptic curve to use for the keypair')
    args = parser.parse_args()

    curve_map = {
        'p256': ec.SECP256R1(),
        'p384': ec.SECP384R1(),
        'p521': ec.SECP521R1(),
    }
    privkey = ec.generate_private_key(curve_map[args.curve])
    pubkey = privkey.public_key()

    private_bytes = privkey.private_numbers().private_value.to_bytes(length=(privkey.key_size + 7) // 8, byteorder='big')
    public_bytes = pubkey.public_bytes(encoding=Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

    print("PRIVATE key: " + str(base64.b64encode(private_bytes)))
    print("PUBLIC key: " + str(base64.b64encode(public_bytes)))
