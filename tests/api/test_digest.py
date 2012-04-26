"""Test digest API"""
from ctypes import byref, c_uint, pointer, c_ubyte
from functools import partial
import platform
import unittest

from tls.api import digest, nid

def expect_fail_system(system):
    "Decorate function with expected failure for OpenSSL on platform"
    def expect_failure(func):
        return unittest.expectedFailure(func)
    def noop(func):
        return func
    if platform.system() == system:
        return expect_failure
    return noop


class DigestTests:
    
    data_short = b'abc'
    data_long = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'

    def test_short(self):
        buf = (c_ubyte * digest.EVP_MAX_MD_SIZE)()
        size = c_uint()
        digest.EVP_DigestUpdate(self.ctx, self.data_short, len(self.data_short))
        digest.EVP_DigestFinal_ex(self.ctx, buf, byref(size))
        hash_value = ''.join('{0:02x}'.format(v) for v in buf[:size.value])
        self.assertEqual(hash_value, self.hash_short)

    def test_long(self):
        buf = (c_ubyte * digest.EVP_MAX_MD_SIZE)()
        size = c_uint()
        digest.EVP_DigestUpdate(self.ctx, self.data_long, len(self.data_long))
        digest.EVP_DigestFinal_ex(self.ctx, buf, byref(size))
        hash_value = ''.join('{0:02x}'.format(v) for v in buf[:size.value])
        self.assertEqual(hash_value, self.hash_long)

    def test_copy(self):
        buf = (c_ubyte * digest.EVP_MAX_MD_SIZE)()
        size = c_uint()
        digest.EVP_DigestUpdate(self.ctx, self.data_short, len(self.data_short))

        digest.EVP_MD_CTX_copy_ex(self.ctx_two, self.ctx)
        digest.EVP_DigestFinal_ex(self.ctx_two, buf, byref(size))
        hash_value = ''.join('{0:02x}'.format(v) for v in buf[:size.value])
        self.assertEqual(hash_value, self.hash_short)

        data = self.data_long[len(self.data_short):]
        digest.EVP_DigestUpdate(self.ctx, data, len(data))
        digest.EVP_DigestFinal_ex(self.ctx, buf, byref(size))
        hash_value = ''.join('{0:02x}'.format(v) for v in buf[:size.value])
        self.assertEqual(hash_value, self.hash_long)


class TestSHA1(unittest.TestCase, DigestTests):

    hash_short = "a9993e364706816aba3e25717850c26c9cd0d89d"
    hash_long = "84983e441c3bd26ebaae4aa1f95129e5e54670f1"

    @classmethod
    def setUpClass(cls):
        cls.md = digest.EVP_sha1()

    def setUp(self):
        self.ctx = digest.EVP_MD_CTX_create()
        digest.EVP_DigestInit_ex(self.ctx, self.md, None)
        self.ctx_two = digest.EVP_MD_CTX_create()
        digest.EVP_DigestInit_ex(self.ctx_two, self.md, None)

    def tearDown(self):
        digest.EVP_MD_CTX_destroy(self.ctx)
        digest.EVP_MD_CTX_destroy(self.ctx_two)


class TestEVP(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        digest.OpenSSL_add_all_digests()

    @classmethod
    def tearDownClass(cls):
        digest.EVP_cleanup()

    def test_init(self):
        ctx = digest.c_evp_md_ctx()
        ctx_p = pointer(ctx)
        self.assertTrue(ctx_p)
        digest.EVP_MD_CTX_init(ctx_p)
        digest.EVP_MD_CTX_cleanup(ctx_p)

    def test_create(self):
        ctx_p = digest.EVP_MD_CTX_create()
        self.assertTrue(ctx_p)
        digest.EVP_MD_CTX_destroy(ctx_p)

    def _test_md_func(self, name, nid_name=None):
        nid_name = name.upper() if nid_name is None else nid_name
        getter = getattr(digest, 'EVP_{0}'.format(name.lower()))
        num = getattr(nid, nid_name)
        md = getter()
        self.assertTrue(md)
        self.assertEqual(digest.EVP_MD_type(md), num)

    def test_md_null_func(self):
        self._test_md_func('md_null', 'undef')

    @expect_fail_system('Darwin')
    def test_dsa_func(self):
        self._test_md_func('dsa')

    def test_dss_func(self):
        self._test_md_func('dss')

    def test_dss1_func(self):
        self._test_md_func('dss1')

    def test_ecdsa_func(self):
        self._test_md_func('ecdsa')

    def test_md2_func(self):
        self._test_md_func('md2')

    def test_md4_func(self):
        self._test_md_func('md4')

    def test_md5_func(self):
        self._test_md_func('md5')

    def test_mdc2_func(self):
        self._test_md_func('mdc2')

    def test_ripemd160_func(self):
        self._test_md_func('ripemd160')

    def test_sha_func(self):
        self._test_md_func('sha')

    def test_sha1_func(self):
        self._test_md_func('sha1')

    def test_sha224_func(self):
        self._test_md_func('sha224')

    def test_sha256_func(self):
        self._test_md_func('sha256')

    def test_sha384_func(self):
        self._test_md_func('sha384')

    def test_sha512_func(self):
        self._test_md_func('sha512')

    def _test_md_name(self, name, nid_name=None):
        nid_name = name.upper() if nid_name is None else nid_name
        md_name = name.encode()
        num = getattr(nid, nid_name)
        md = digest.EVP_get_digestbyname(md_name)
        self.assertTrue(md)
        self.assertEqual(digest.EVP_MD_type(md), num)

    def test_dsa_name(self):
        self._test_md_name('DSA', 'DSS')

    def test_dsa_name(self):
        self._test_md_name('DSA-SHA1', 'DSS1')

    def test_ecdsa_name(self):
        self._test_md_name('ecdsa-with-SHA1', 'ECDSA')

    @expect_fail_system('Darwin')
    def test_md2_name(self):
        self._test_md_name('MD2')

    def test_md4_name(self):
        self._test_md_name('MD4')

    def test_md5_name(self):
        self._test_md_name('MD5')

    def test_mdc2_name(self):
        self._test_md_name('MDC2')

    def test_ripemd160_name(self):
        self._test_md_name('RIPEMD160')

    def test_sha_name(self):
        self._test_md_name('SHA')

    def test_sha1_name(self):
        self._test_md_name('SHA1')

    def test_sha224_name(self):
        self._test_md_name('SHA224')

    def test_sha256_name(self):
        self._test_md_name('SHA256')

    def test_sha384_name(self):
        self._test_md_name('SHA384')

    def test_sha512_name(self):
        self._test_md_name('SHA512')

    def _test_md_nid(self, nid, name):
        self.assertEqual(name, digest.OBJ_nid2sn(nid))
        md = digest.EVP_get_digestbynid(nid)
        self.assertTrue(md)

    @expect_fail_system('Darwin')
    def test_md2_nid(self):
        self._test_md_nid(nid.MD2, b'MD2')

    def test_md4_nid(self):
        self._test_md_nid(nid.MD4, b'MD4')

    def test_md5_nid(self):
        self._test_md_nid(nid.MD5, b'MD5')

    def test_mdc2_nid(self):
        self._test_md_nid(nid.MDC2, b'MDC2')

    def test_ripemd160_nid(self):
        self._test_md_nid(nid.RIPEMD160, b'RIPEMD160')

    def test_sha_nid(self):
        self._test_md_nid(nid.SHA, b'SHA')

    def test_sha1_nid(self):
        self._test_md_nid(nid.SHA1, b'SHA1')

    def test_sha224_nid(self):
        self._test_md_nid(nid.SHA224, b'SHA224')

    def test_sha256_nid(self):
        self._test_md_nid(nid.SHA256, b'SHA256')

    def test_sha384_nid(self):
        self._test_md_nid(nid.SHA384, b'SHA384')

    def test_sha512_nid(self):
        self._test_md_nid(nid.SHA512, b'SHA512')
