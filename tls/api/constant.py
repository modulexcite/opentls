"""constants used in openssl"""

# BIO_CTRL_*
BIO_CTRL_RESET = 1
BIO_CTRL_EOF = 2
BIO_CTRL_INFO = 3
BIO_CTRL_SET = 4
BIO_CTRL_GET = 5
BIO_CTRL_PUSH = 6
BIO_CTRL_POP = 7
BIO_CTRL_GET_CLOSE = 8
BIO_CTRL_SET_CLOSE = 9
BIO_CTRL_PENDING = 10
BIO_CTRL_FLUSH = 11
BIO_CTRL_DUP = 12
BIO_CTRL_WPENDING = 13
BIO_CTRL_SET_CALLBACK = 14
BIO_CTRL_GET_CALLBACK = 15
BIO_CTRL_SET_FILENAME = 30
BIO_CTRL_DGRAM_CONNECT = 31
BIO_CTRL_DGRAM_SET_CONNECTED = 32
BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33
BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34
BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35
BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36
BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37
BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38
BIO_CTRL_DGRAM_MTU_DISCOVER = 39
BIO_CTRL_DGRAM_QUERY_MTU = 40
BIO_CTRL_DGRAM_GET_MTU = 41
BIO_CTRL_DGRAM_SET_MTU = 42
BIO_CTRL_DGRAM_MTU_EXCEEDED = 43
BIO_CTRL_DGRAM_GET_PEER = 46
BIO_CTRL_DGRAM_SET_PEER = 44
BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45

# BIO_C_*
BIO_C_SET_CONNECT = 100
BIO_C_DO_STATE_MACHINE = 101
BIO_C_SET_NBIO = 102
BIO_C_SET_PROXY_PARAM = 103
BIO_C_SET_FD = 104
BIO_C_GET_FD = 105
BIO_C_SET_FILE_PTR = 106
BIO_C_GET_FILE_PTR = 107
BIO_C_SET_FILENAME = 108
BIO_C_SET_SSL = 109
BIO_C_GET_SSL = 110
BIO_C_SET_MD = 111
BIO_C_GET_MD = 112
BIO_C_GET_CIPHER_STATUS = 113
BIO_C_SET_BUF_MEM = 114
BIO_C_GET_BUF_MEM_PTR = 115
BIO_C_GET_BUFF_NUM_LINES = 116
BIO_C_SET_BUFF_SIZE = 117
BIO_C_SET_ACCEPT = 118
BIO_C_SSL_MODE = 119
BIO_C_GET_MD_CTX = 120
BIO_C_GET_PROXY_PARAM = 121
BIO_C_SET_BUFF_READ_DATA = 122
BIO_C_GET_CONNECT = 123
BIO_C_GET_ACCEPT = 124
BIO_C_SET_SSL_RENEGOTIATE_BYTES = 125
BIO_C_GET_SSL_NUM_RENEGOTIATES = 126
BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127
BIO_C_FILE_SEEK = 128
BIO_C_GET_CIPHER_CTX = 129
BIO_C_SET_BUF_MEM_EOF_RETURN = 130
BIO_C_SET_BIND_MODE = 131
BIO_C_GET_BIND_MODE = 132
BIO_C_FILE_TELL = 133
BIO_C_GET_SOCKS = 134
BIO_C_SET_SOCKS = 135
BIO_C_SET_WRITE_BUF_SIZE = 136
BIO_C_GET_WRITE_BUF_SIZE = 137
BIO_C_MAKE_BIO_PAIR = 138
BIO_C_DESTROY_BIO_PAIR = 139
BIO_C_GET_WRITE_GUARANTEE = 140
BIO_C_GET_READ_REQUEST = 141
BIO_C_SHUTDOWN_WR = 142
BIO_C_NREAD0 = 143
BIO_C_NREAD = 144
BIO_C_NWRITE0 = 145
BIO_C_NWRITE = 146
BIO_C_RESET_READ_REQUEST = 147
BIO_C_SET_MD_CTX = 148

# EVP_*
EVP_MAX_MD_SIZE = 64
EVP_MAX_KEY_LENGTH = 32
EVP_MAX_IV_LENGTH = 16
EVP_MAX_BLOCK_LENGTH = 32
