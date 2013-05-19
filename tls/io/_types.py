"""BIO type constants"""
from __future__ import absolute_import, division, print_function
from tls.c import api

__all__ = ['BIO_TYPES']


BIO_TYPES = {}


def _populate_bio_types():
    "Dynamically populate module with BIO type contants from tls.c.api"
    for name in dir(api.openssl):
        if name.startswith('BIO_TYPE_'):
            value = getattr(api.openssl, name)
            BIO_TYPES[value] = name
            globals()[name] = value
            __all__.append(name)

_populate_bio_types()
