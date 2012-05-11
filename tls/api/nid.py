"NID values"

__all__ = []

# NID_*
undef = 0
DSS = 66
DSS1 = 116
ECDSA = 416
MD2 = 3
MD4 = 257
MD5 = 4
MDC2 = 95
RIPEMD160 = 117
SHA = 41
SHA1 = 64
SHA256 = 672
SHA384 = 673
SHA512 = 674
SHA224 = 675

__all__.extend(name for name in locals() if name[0].isalpha())
