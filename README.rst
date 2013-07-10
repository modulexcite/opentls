OpenTLS
=======
**YOU (PROBABLY) SHOULD NOT BE USING THIS PACKAGE.
I AM NOT AN EXPERT IN CRYPTOGRAPHIC SOFTWARE.
IT HAS NOT BE BEEN REVIEWED BY ANYBODY WHO IS.**

Purpose
-------
Provide an area for with cryptographic APIs in Python,
implemented using `OpenSSL <http://openssl.org/>`_.

Motivation
-----------
Doing encryption in *correctly* in Python is hard.
In spite of `The Zen of Python <http://www.python.org/dev/peps/pep-0020/>`_,
there is often no obvious way to do something.
This repository is a place
to both experiment and learn about
using OpenSSL to implement cryptographic APIs.

Legal
-----
This package is distributed under the
`Apache License 2.0 <http://www.tldrlegal.com/license/APACHE2>`_.

Status
------
|build_status| Five usable modules have been implemented.

``tls.cipherlib`` is a common interface to
symmetric ciphers for Python.
The API is modeled after 
Python's hashlib module.

``tls.hashlib`` is an implementation
of Python's hashlib module
using OpenSSL's cryptographically secure hash functions.

``tls.hmac`` is an implementation
of Python's hmac module
using OpenSSL's HMAC functions.
It differs slightly
from the standard library implementation
because OpenSSL's HMAC objects
can not be copied.

``tls.kdf`` implements
password based
key derivation functions from
the PKCS5 standard

``tls.random`` is an implementation
of Python's random module
using OpenSSL's pseudo-random number API.
It is suitable for cryptographic use.

Additionally, some parts of OpenSSL's APIs have been wrapped
using `cffi <https://cffi.readthedocs.org/en/latest/index.html>`_.
This wrapping is limited to:

* buffered io 
  * sinks (null, memory and files)
  * filters (null, zlib, base64 and message digests)
* error message handling
* message digests (cryptographically secure hash functions)
* symmetric ciphers
* random data (pseudo and cryptographically strong)

The low level OpenSSL APIs are in the `tls.c.api` object.

Experiments
-----------
Here are some of the problems
I have thought about experimenting with
solutions for.

Reusing SSL Contexts
^^^^^^^^^^^^^^^^^^^^
The standard libraries SSL module
creates a new context for each connection.
If you are doing SSL client authentication
with a client certificate that is encrypted
it is necessary to provide the password
for every request.

I have thought about implementing
a replacement module
that can be monkey patched
in place of the current implementation.

SNI Support
^^^^^^^^^^^
`Server name identification <http://en.wikipedia.org/wiki/Server_Name_Indication>`_
(SNI) is an extension to TLS
that adds support for
`virtual hosting <http://en.wikipedia.org/wiki/Virtual_hosting#Name-based>`_
to TLS enabled servers.
The current SSL module in the standard library
does not support SNI.
I'm interested in determining how support is enabled.

SSL Session Resumption
^^^^^^^^^^^^^^^^^^^^^^
Currently there is no way to support 
SSL session resumption between server restarts
or across multiple hosts.
I am not even sure if session resumption is enabled
for connections to the same process.

I have thought about implementing a plugin API
for storing SSL session state.
`Redis <http://redis.io/>`_ is
an obvious choice for an initial implementation.

Symmetric Encryption
^^^^^^^^^^^^^^^^^^^^
I have not been able to find a simple API
that handles the complexities of encrypting a file.
It is usually necessary for the developer to
know and understand when and how to:

* deriving the key from a password
* generating an initialization vector
* using a message authentication code
* applying padding correctly

I have thought about implementing a simple API
that manages these automatically for the developer.

Buffered IO Implementations in Python
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
OpenSSL has an IO abstraction standard
known as buffered io (BIO).
I'm am interesting in determining
if the API could be exposed to enable
new BIO methods to be implemented in Python.
A possible use case for this is
to support SSL over new transport layers,
such as `SOCKS <http://en.wikipedia.org/wiki/SOCKS>`_ proxies.

Documentation
-------------
There is none.

A `Sphinx <http://sphinx.pocoo.org/>`_ project skeleton
has been created for use.
But as yet there are no documentation
has been written.

.. |build_status| image:: https://secure.travis-ci.org/alex/opentls.png?branch=master
   :target: http://travis-ci.org/alex/opentls
