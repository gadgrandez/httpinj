import time
import zlib
import re
from common import *


class payload(CommonPayload):
    load_delay = 5
    hash_secret = "change me"
    content = """
    <html>
    <body>
    <h1>Please wait...</h1>
    </body>
    </html>
    """
    content_length = len(content)

    @classmethod
    def http_payload(cls):
        bypass_value = cls.bypass_generate()

        header = "HTTP/1.1 200 OK\r\nServer: httpinj\r\nConnection: close\r\nContent-type: text/html\r\nRefresh: %s\r\nContent-length: %s\r\nSet-Cookie: %s=%s;path=/;Max-Age=%s\r\n\r\n" % (
        cls.load_delay, cls.content_length, cls.bypass_name, bypass_value, cls.bypass_ttl)

        return header + cls.content

    @classmethod
    def hash(cls, data):
        def ror( dword, bits ):
            return ( dword >> bits | dword << ( 32 - bits ) ) & 0xFFFFFFFF

        h = 0
        for c in str( data + "\x00" ):
            h  = ror( h, 13 )
            h += ord( c )
        return h

    @classmethod
    def bypass_generate(cls):
        # refreshes every 10s
        ts = str(time.time())[:9]
        return str(cls.hash(ts + cls.hash_secret))

    @classmethod
    def bypass_validate(cls, data):
        bypass = cls.bypass_generate()
        if bypass in data:
            return True
        else:
            return False
