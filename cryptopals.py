#!/usr/bin/env python3
import cryptography.hazmat.primitives.ciphers as crypto
A, D = (lambda x: (x, dict(zip(x, range(64))) | {61: 0}))(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
b64e = lambda b: b"".join(map(lambda x: bytes(A[int.from_bytes(b[x: x + 3]) >> 6 * i & 63] for i in range(4)[::-1]), range(0, len(b :=  b + (m := -len(b) % 3) * b"\0"), 3)))[:-m or None] + m * b"="
b64d, b64f = lambda s: b"".join(sum(D[x[i]]<<6*(3-i)for i in range(4)).to_bytes(3)for x in zip(*(s[i::4]for i in range(4)),strict=1))[:-s.count(61)or None], lambda f: b64d(b"".join(f.read().split()))
xor, rxor = lambda x, y: bytes(i ^ j for i, j in zip(x, y)), lambda b, k: bytes(b[i] ^ k[i % len(k)] for i in range(len(b)))
FREQ = dict(zip(range(97, 123), (65174,12425,21734,34984,104144,19788,15861,49289,55809,903,5053,33149,20212,56451,59630,13764,861,49756,51576,72936,22513,8290,17127,1369,14598,783))) | {32: 191821}
english_score = lambda b: sum(FREQ.get(i, 0) / 1e6 for i in b.lower()) / len(b)
break_singlebyte_xor = lambda b: max((english_score(rxor(b, bytes([k]))), bytes([k])) for k in range(256))[1]
detect_singlebyte_xor = lambda c: max((english_score(rxor(b, break_singlebyte_xor(b))), b) for b in c)[1]
hamming = lambda x, y: sum(int.bit_count(i) for i in xor(x, y))
break_repeatingkey_xor = lambda c, r=range(2,41): b"".join(map(lambda i: break_singlebyte_xor(c[i::k]), range(k := min((sum(hamming(c[i:i+k], c[i+k:i+2*k]) for i in range(100))/k, k) for k in r)[1])))
aes_ecb = lambda b, k, mode='e': (lambda x: x.decryptor() if mode=='d' else x.encryptor())(crypto.Cipher(crypto.algorithms.AES(k), crypto.modes.ECB())).update(b)
detect_ecb = lambda c, bs=16: min((len({b[i:i+bs] for i in range(0, len(b), bs)}), b) for b in c)[1]
pkcs7_pad = lambda b, bs=16: b + (lambda x: x * bytes([x]))(bs - len(b) % bs)
is_pkcs7_padded = lambda b: all(i == b[-1] for i in b[-b[-1]:]) if len(b) else 0
pkcs7_unpad = lambda b: b[:-b[-1]] if is_pkcs7_padded(b) else b
aes_cbc_encrypt = lambda p, k, iv=b"\0"*16, bs=16: b"".join(iv := aes_ecb(xor(p[i:i+bs], iv), k, 'e') for i in range(0, len(p), bs))
aes_cbc_decrypt = lambda c, k, iv=b"\0"*16, bs=16: b"".join(xor(iv, aes_ecb(iv := c[i:i+bs], k, 'd')) for i in range(0, len(c), bs))

if __name__ == "__main__":

    with open("out.txt", "rb") as f:
        out = f.read()

    # 1
    assert (lambda x, y: b64e(x) == y and x == b64d(y)) (
        b"I'm killing your brain like a poisonous mushroom",
        b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    )

    # 2
    assert (lambda x, y, z: xor(x, y) == z) (
        bytes.fromhex("1c0111001f010100061a024b53535009181c"),
        bytes.fromhex("686974207468652062756c6c277320657965"),
        bytes.fromhex("746865206b696420646f6e277420706c6179"),
    )

    # 3
    assert (lambda x, y, z: break_singlebyte_xor(x) == y and rxor(x, y) == z) (
        bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"),
        b"X", b"Cooking MC's like a pound of bacon",
    )

    # 4
    with open("4.txt") as f:
        assert (lambda c, x, y: detect_singlebyte_xor(c) == x and rxor(x, break_singlebyte_xor(x)) == y) (
            map(bytes.fromhex, f),
            bytes.fromhex("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"),
            b"Now that the party is jumping\n",
        )

    # 5
    assert rxor(
        b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b"ICE",
    ) == bytes.fromhex(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
        "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )

    # 6
    assert hamming(b"this is a test", b"wokka wokka!!!") == 37
    with open("6.txt", "rb") as f:
        assert (lambda x, y, z: break_repeatingkey_xor(x) == y and rxor(x, y) == z)(
            b64f(f), b"Terminator X: Bring the noise", out
        )

    # 7
    with open("7.txt", "rb") as f:
        assert aes_ecb(b64f(f), b"YELLOW SUBMARINE", mode='d') == out + b"\4\4\4\4"

    # 8
    with open("8.txt", "rb") as f:
        assert detect_ecb(map(bytes.fromhex, f)) == bytes.fromhex(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf"
            "9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a"
            "08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4f"
            "d5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
        )

    # 9
    assert (lambda x, y, bs: pkcs7_pad(x, bs) == y and pkcs7_unpad(y) == x) (
        b"YELLOW SUBMARINE", b"YELLOW SUBMARINE\4\4\4\4", bs=20,
    )

    # 10
    with open("10.txt", "rb") as f:
        assert pkcs7_unpad(aes_cbc_decrypt(b64f(f), b"YELLOW SUBMARINE")) == out
