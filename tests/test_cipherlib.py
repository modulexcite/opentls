"""Test Python cipherlib API module"""
from __future__ import absolute_import, division, print_function
import math
import mock

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tls import cipherlib
from tls.c import api


if hasattr(str, 'decode'):
    int2byte = chr
else:
    int2byte = lambda i: bytes((i,))


class TestAlgorithms(unittest.TestCase):
    def test_guaranteed(self):
        self.assertEqual(set(), cipherlib.algorithms_guaranteed)

    def test_available(self):
        self.assertGreater(len(cipherlib.algorithms_available), 0)
        self.assertIn(b'AES-128-CBC', cipherlib.algorithms_available)


class CipherObject(object):

    def setUp(self):
        self.cipher = cipherlib.Cipher(self.ENCRYPT, self.ALGORITHM, self.DIGEST)

    def tearDown(self):
        if hasattr(self, 'cipher'):
            del self.cipher

    def test_algorithm(self):
        self.assertEqual(self.ALGORITHM, self.cipher.algorithm)

    def test_digest(self):
        self.assertEqual(self.DIGEST, self.cipher.digest)

    def test_digest_size(self):
        self.assertEqual(self.DIGEST_SIZE, self.cipher.digest_size)

    def test_block_size(self):
        self.assertEqual(self.LEN_BLOCK, self.cipher.block_size)

    def test_ivector_len(self):
        self.assertEqual(self.LEN_IV, self.cipher.ivector_len)

    def test_key_len(self):
        self.assertEqual(self.LEN_KEY, self.cipher.key_len)

    def test_decrypting(self):
        self.assertNotEqual(self.ENCRYPT, self.cipher.decrypting)

    def test_encrypting(self):
        self.assertEqual(self.ENCRYPT, self.cipher.encrypting)

    def test_mode(self):
        self.assertEqual(self.MODE, self.cipher.mode)

    def test_name(self):
        self.assertEqual(self.ALGORITHM, self.cipher.name)

    def test_invalid_name(self):
        self.assertRaises(ValueError, cipherlib.Cipher, self.ENCRYPT, b'UNDEF')

    def test_initialised(self):
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.assertTrue(self.cipher.is_initialised)

    def test_initialise_invalid_key(self):
        self.assertRaises(ValueError, self.cipher.initialise,
                self.KEY + b'\FF', self.IVECTOR)

    def test_initialise_invalid_ivector(self):
        self.assertRaises(ValueError, self.cipher.initialise,
                self.KEY, self.IVECTOR + b'\FF')

    def test_update(self):
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update(b'\x00' * self.LEN_BLOCK)

    def test_update_invalid(self):
        self.assertRaises(ValueError, self.cipher.update, b'\x00' * self.LEN_BLOCK)

    def test_finish(self):
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.finish()

    def test_ciphertext(self):
        if not self.ENCRYPT:
            return
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update(b'\x00' * self.LEN_BLOCK)
        self.cipher.finish()
        ciphertext = self.cipher.ciphertext()
        length = math.ceil(float(self.LEN_BLOCK + self.cipher.digest_size + 1)
                / self.LEN_BLOCK) * self.LEN_BLOCK
        self.assertEqual(len(ciphertext), length)

    def test_ciphertext_invalid(self):
        if self.ENCRYPT:
            return
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update(b'\x00' * self.LEN_BLOCK)
        self.cipher.finish()
        self.assertRaises(ValueError, self.cipher.ciphertext)

#   def test_plaintext(self):
#       if self.ENCRYPT:
#           return
#       self.cipher.initialise(self.KEY, self.IVECTOR)
#       self.cipher.update('\x00' * self.LEN_BLOCK)
#       self.cipher.finish()
#       plaintext = self.cipher.plaintext()
#       self.assertEqual(len(plaintext), self.LEN_BLOCK)

    def test_plaintext_invalid(self):
        if not self.ENCRYPT:
            return
        self.cipher.initialise(self.KEY, self.IVECTOR)
        self.cipher.update(b'\x00' * self.LEN_BLOCK)
        self.cipher.finish()
        self.assertRaises(ValueError, self.cipher.plaintext)

    def test_weakref_bio(self):
        BIO_free_all_cleanup = api.BIO_free_all
        with mock.patch('tls.c.api.BIO_free_all') as cleanup_mock:
            cleanup_mock.side_effect = BIO_free_all_cleanup
            del self.cipher
            self.assertEqual(cleanup_mock.call_count, 1)


class TestAesEncryptObject(CipherObject, unittest.TestCase):

    ALGORITHM = b'AES-128-CBC'
    DIGEST = b'SHA1'
    DIGEST_SIZE = 20
    ENCRYPT = True
    IVECTOR = b'\x00' * 16
    KEY = b'\x00' * 16
    LEN_BLOCK = 16
    LEN_IV = 16
    LEN_KEY = 16
    MODE = cipherlib.EVP_CIPH_CBC_MODE

    def test_key_len_set(self):
        def change_key_len(length):
            self.cipher.key_len = length
        self.assertRaises(ValueError, change_key_len, 8)


class TestRc4DecryptObject(CipherObject, unittest.TestCase):

    ALGORITHM = b'RC4'
    DIGEST = b'MD5'
    DIGEST_SIZE = 16
    ENCRYPT = False
    IVECTOR = b''
    KEY = b'\x00' * 16
    LEN_BLOCK = 1
    LEN_IV = 0
    LEN_KEY = 16
    MODE = cipherlib.EVP_CIPH_STREAM_CIPHER

    def test_key_len_set(self):
        self.cipher_key_len = 8
        # self.assertEqual(8, self.cipher.key_len)


class TestDesEncryptObject(CipherObject, unittest.TestCase):

    ALGORITHM = b'DES-ECB'
    DIGEST = None
    DIGEST_SIZE = 0
    ENCRYPT = True
    IVECTOR = b''
    KEY = b'\x00' * 8
    LEN_BLOCK = 8
    LEN_IV = 0
    LEN_KEY = 8
    MODE = cipherlib.EVP_CIPH_ECB_MODE

    def test_key_len_set(self):
        def change_key_len(length):
            self.cipher.key_len = length
        self.assertRaises(ValueError, change_key_len, 16)


class CipherTests(object):
    def _encrypt(self):
        cipher = cipherlib.Cipher(True, self.algorithm)
        cipher.initialise(self.key, self.iv)
        cipher.update(self.plaintext)
        cipher.finish()
        return cipher.ciphertext()

    def _decrypt(self, data):
        cipher = cipherlib.Cipher(False, self.algorithm)
        cipher.initialise(self.key, self.iv)
        cipher.update(data)
        cipher.finish()
        return cipher.plaintext()

    def test_encrypt_decrypt(self):
        result = self._encrypt()
        self.assertEqual(result[:len(self.ciphertext)], self.ciphertext)
        result = self._decrypt(result)
        self.assertEqual(result[:len(self.plaintext)], self.plaintext)

    def test_bitflip_data_decrypt(self):
        result = self._encrypt()
        result = int2byte(ord(result[:1]) ^ 0x80) + result[1:]
        self.assertRaises(ValueError, self._decrypt, result)

    def test_bitflip_hmac_decrypt(self):
        result = self._encrypt()
        pos = len(self.ciphertext)
        result = (result[:pos]
                + int2byte(ord(result[pos:pos + 1]) ^ 0x80)
                + result[pos + 1:])
        self.assertRaises(ValueError, self._decrypt, result)

    def test_bitflip_padding_decrypt(self):
        result = self._encrypt()
        result = result[:-1] + int2byte(ord(result[-1:]) ^ 0x01)
        self.assertRaises(ValueError, self._decrypt, result)

    def test_trunc_data_decrypt(self):
        result = self._encrypt()
        result = result[1:]
        self.assertRaises(ValueError, self._decrypt, result)

    def test_trunc_hmac_decrypt(self):
        result = self._encrypt()
        pos = len(self.ciphertext)
        result = result[:pos] + result[pos + 1:]
        self.assertRaises(ValueError, self._decrypt, result)

    def test_trunc_padding_decrypt(self):
        result = self._encrypt()
        result = result[:-1]
        self.assertRaises(ValueError, self._decrypt, result)


class Test_AES_ECB_128_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-ECB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = None
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b":\xd7{\xb4\rz6`\xa8\x9e\xca\xf3$f\xef\x97"


class Test_AES_ECB_128_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-ECB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = None
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"\xf5\xd3\xd5\x85\x03\xb9i\x9d\xe7\x85\x89Z\x96\xfd\xba\xaf"


class Test_AES_ECB_128_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-ECB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = None
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"C\xb1\xcd\x7fY\x8e\xce#\x88\x1b\x00\xe3\xed\x03\x06\x88"


class Test_AES_ECB_128_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-ECB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = None
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"{\x0cx^'\xe8\xad?\x82# q\x04r]\xd4"


class Test_AES_ECB_192_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-ECB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = None
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"\xbd3O\x1dnE\xf2_\xf7\x12\xa2\x14W\x1f\xa5\xcc"


class Test_AES_ECB_192_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-ECB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = None
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"\x97A\x04\x84m\n\xd3\xadw4\xec\xb3\xec\xeeN\xef"


class Test_AES_ECB_192_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-ECB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = None
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"\xefz\xfd\"p\xe2\xe6\n\xdc\xe0\xba/\xac\xe6DN"


class Test_AES_ECB_192_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-ECB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = None
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"\x9aKA\xbas\x8dlr\xfb\x16i\x16\x03\xc1\x8e\x0e"


class Test_AES_ECB_256_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-ECB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = None
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"\xf3\xee\xd1\xbd\xb5\xd2\xa0<\x06KZ~=\xb1\x81\xf8"


class Test_AES_ECB_256_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-ECB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = None
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"Y\x1c\xcb\x10\xd4\x10\xed&\xdc[\xa7J16(p"


class Test_AES_ECB_256_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-ECB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = None
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"\xb6\xed!\xb9\x9c\xa6\xf4\xf9\xf1S\xe7\xb1\xbe\xaf\xed\x1d"


class Test_AES_ECB_256_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-ECB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = None
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"#0Kz9\xf9\xf3\xff\x06}\x8d\x8f\x9e$\xec\xc7"


class Test_AES_CBC_128_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CBC"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"vI\xab\xac\x81\x19\xb2F\xce\xe9\x8e\x9b\x12\xe9\x19}"


class Test_AES_CBC_128_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CBC"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"vI\xab\xac\x81\x19\xb2F\xce\xe9\x8e\x9b\x12\xe9\x19}"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"P\x86\xcb\x9bPr\x19\xee\x95\xdb\x11:\x91vx\xb2"


class Test_AES_CBC_128_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CBC"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"P\x86\xcb\x9bPr\x19\xee\x95\xdb\x11:\x91vx\xb2"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"s\xbe\xd6\xb8\xe3\xc1t;q\x16\xe6\x9e\"\"\x95\x16"


class Test_AES_CBC_128_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CBC"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"s\xbe\xd6\xb8\xe3\xc1t;q\x16\xe6\x9e\"\"\x95\x16"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"?\xf1\xca\xa1h\x1f\xac\t\x12\x0e\xca0u\x86\xe1\xa7"


class Test_AES_CBC_192_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CBC"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"O\x02\x1d\xb2C\xbcc=qx\x18:\x9f\xa0q\xe8"


class Test_AES_CBC_192_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CBC"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"O\x02\x1d\xb2C\xbcc=qx\x18:\x9f\xa0q\xe8"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"\xb4\xd9\xad\xa9\xad}\xed\xf4\xe5\xe78v?i\x14Z"


class Test_AES_CBC_192_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CBC"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"\xb4\xd9\xad\xa9\xad}\xed\xf4\xe5\xe78v?i\x14Z"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"W\x1b$ \x12\xfbz\xe0\x7f\xa9\xba\xac=\xf1\x02\xe0"


class Test_AES_CBC_192_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CBC"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"W\x1b$ \x12\xfbz\xe0\x7f\xa9\xba\xac=\xf1\x02\xe0"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"\x08\xb0\xe2y\x88Y\x88\x81\xd9 \xa9\xe6OV\x15\xcd"


class Test_AES_CBC_256_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CBC"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"\xf5\x8cL\x04\xd6\xe5\xf1\xbaw\x9e\xab\xfb_{\xfb\xd6"


class Test_AES_CBC_256_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CBC"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\xf5\x8cL\x04\xd6\xe5\xf1\xbaw\x9e\xab\xfb_{\xfb\xd6"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"\x9c\xfcN\x96~\xdb\x80\x8dg\x9fw{\xc6p,}"


class Test_AES_CBC_256_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CBC"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\x9c\xfcN\x96~\xdb\x80\x8dg\x9fw{\xc6p,}"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"9\xf23i\xa9\xd9\xba\xcf\xa50\xe2c\x04#\x14a"


class Test_AES_CBC_256_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CBC"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"9\xf23i\xa9\xd9\xba\xcf\xa50\xe2c\x04#\x14a"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xdal\x19\x07\x8cj\x9d\x1b"


class Test_AES_CFB_128_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b";?\xd9.\xb7-\xad 34I\xf8\xe8<\xfbJ"


class Test_AES_CFB_128_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b";?\xd9.\xb7-\xad 34I\xf8\xe8<\xfbJ"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"\xc8\xa6E7\xa0\xb3\xa9?\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b"


class Test_AES_CFB_128_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"\xc8\xa6E7\xa0\xb3\xa9?\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"&u\x1fg\xa3\xcb\xb1@\xb1\x80\x8c\xf1\x87\xa4\xf4\xdf"


class Test_AES_CFB_128_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-CFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"&u\x1fg\xa3\xcb\xb1@\xb1\x80\x8c\xf1\x87\xa4\xf4\xdf"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"\xc0K\x055|]\x1c\x0e\xea\xc4\xc6o\x9f\xf7\xf2\xe6"


class Test_AES_CFB_192_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"\xcd\xc8\ro\xdd\xf1\x8c\xab4\xc2Y\t\xc9\x9aAt"


class Test_AES_CFB_192_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"\xcd\xc8\ro\xdd\xf1\x8c\xab4\xc2Y\t\xc9\x9aAt"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"g\xce\x7f\x7f\x81\x176!\x96\x1a+p\x17\x1d=z"


class Test_AES_CFB_192_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"g\xce\x7f\x7f\x81\x176!\x96\x1a+p\x17\x1d=z"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b".\x1e\x8a\x1d\xd5\x9b\x88\xb1\xc8\xe6\x0f\xed\x1e\xfa\xc4\xc9"


class Test_AES_CFB_192_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-CFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b".\x1e\x8a\x1d\xd5\x9b\x88\xb1\xc8\xe6\x0f\xed\x1e\xfa\xc4\xc9"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"\xc0_\x9f\x9c\xa9\x83O\xa0B\xae\x8f\xbaXK\t\xff"


class Test_AES_CFB_256_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"\xdc~\x84\xbf\xday\x16K~\xcd\x84\x86\x98]8`"


class Test_AES_CFB_256_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\xdc~\x84\xbf\xday\x16K~\xcd\x84\x86\x98]8`"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"9\xff\xed\x14;(\xb1\xc82\x11<c1\xe5@{"


class Test_AES_CFB_256_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"9\xff\xed\x14;(\xb1\xc82\x11<c1\xe5@{"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"\xdf\x10\x13$\x15\xe5K\x92\xa1>\xd0\xa8&z\xe2\xf9"


class Test_AES_CFB_256_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-CFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\xdf\x10\x13$\x15\xe5K\x92\xa1>\xd0\xa8&z\xe2\xf9"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"u\xa3\x85t\x1a\xb9\xce\xf8 1b=U\xb1\xe4q"


class Test_AES_OFB_128_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-OFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b";?\xd9.\xb7-\xad 34I\xf8\xe8<\xfbJ"


class Test_AES_OFB_128_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-OFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"P\xfeg\xcc\x99m2\xb6\xda\t7\xe9\x9b\xaf\xec`"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"w\x89P\x8d\x16\x91\x8f\x03\xf5<R\xda\xc5N\xd8%"


class Test_AES_OFB_128_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-OFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"\xd9\xa4\xda\xda\x08\x92#\x9fk\x8b=v\x80\xe1Vt"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"\x97@\x05\x1e\x9c_\xec\xf6CD\xf7\xa8\"`\xed\xcc"


class Test_AES_OFB_128_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-128-OFB"
    key = b"+~\x15\x16(\xae\xd2\xa6\xab\xf7\x15\x88\t\xcfO<"
    iv = b"\xa7\x88\x19X?\x03\x08\xe7\xa6\xbf6\xb18j\xbf#"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"0Le(\xf6Y\xc7xf\xa5\x10\xd9\xc1\xd6\xae^"


class Test_AES_OFB_192_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-OFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"\xcd\xc8\ro\xdd\xf1\x8c\xab4\xc2Y\t\xc9\x9aAt"


class Test_AES_OFB_192_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-OFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"\xa6\t\xb3\x8d\xf3\xb1\x13=\xdd\xff'\x18\xba\tV^"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"\xfc\xc2\x8b\x8dLc\x83|\t\xe8\x17\x00\xc1\x10\x04\x01"


class Test_AES_OFB_192_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-OFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"R\xef\x01\xdaR`/\xe0\x97_x\xac\x84\xbf\x8aP"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"\x8d\x9a\x9a\xea\xc0\xf6YoU\x9cmM\xafY\xa5\xf2"


class Test_AES_OFB_192_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-192-OFB"
    key = b"\x8es\xb0\xf7\xda\x0edR\xc8\x10\xf3+\x80\x90y\xe5b\xf8\xea\xd2R,k{"
    iv = b"\xbdR\x86\xacc\xaa\xbd~\xb0g\xacT\xb5S\xf7\x1d"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"m\x9f \x08W\xcal>\x9c\xacRK\xd9\xac\xc9*"


class Test_AES_OFB_256_v1(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-OFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    plaintext = b"k\xc1\xbe\xe2.@\x9f\x96\xe9=~\x11s\x93\x17*"
    ciphertext = b"\xdc~\x84\xbf\xday\x16K~\xcd\x84\x86\x98]8`"


class Test_AES_OFB_256_v2(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-OFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\xb7\xbf:]\xf49\x89\xdd\x97\xf0\xfa\x97\xeb\xce/J"
    plaintext = b"\xae-\x8aW\x1e\x03\xac\x9c\x9e\xb7o\xacE\xaf\x8eQ"
    ciphertext = b"O\xeb\xdcg@\xd2\x0b:\xc8\x8fj\xd8*O\xb0\x8d"


class Test_AES_OFB_256_v3(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-OFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"\xe1\xc6V0^\xd1\xa7\xa6V8\x05to\xe0>\xdc"
    plaintext = b"0\xc8\x1cF\xa3\\\xe4\x11\xe5\xfb\xc1\x19\x1a\nR\xef"
    ciphertext = b"q\xabG\xa0\x86\xe8n\xed\xf3\x9d\x1c[\xba\x97\xc4\x08"


class Test_AES_OFB_256_v4(CipherTests, unittest.TestCase):
    algorithm = b"AES-256-OFB"
    key = b"`=\xeb\x10\x15\xcaq\xbe+s\xae\xf0\x85}w\x81\x1f5,\x07;a\x08\xd7-\x98\x10\xa3\t\x14\xdf\xf4"
    iv = b"Ac[\xe6%\xb4\x8a\xfc\x16f\xddB\xa0\x9d\x96\xe7"
    plaintext = b"\xf6\x9f$E\xdfO\x9b\x17\xad+A{\xe6l7\x10"
    ciphertext = b"\x01&\x14\x1dg\xf3{\xe8S\x8fZ\x8b\xe7@\xe4\x84"
