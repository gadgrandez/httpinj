import time
import zlib
import re
from common import *


class payload(CommonPayload):
    load_delay = 5
    static_key = "change_me"
    content = """
    <html>
    <body>
    <h1>Please reload</h1>
    </body>
    </html>
    """
    content_length = len(content)

    @classmethod
    def http_payload(cls):
        bypass_value = cls.bypass_generate()

        header = "HTTP/1.1 200 OK\r\nServer: httpinj\r\nConnection: close\r\nContent-type: text/html\r\nContent-length: %s\r\nSet-Cookie: %s=%s;path=/;Max-Age=%s\r\n\r\n" % (
        cls.content_length, cls.bypass_name, bypass_value, cls.bypass_ttl)

        return header + cls.content

    @classmethod
    def bypass_generate(cls):
        return cls.static_key

    @classmethod
    def bypass_validate(cls, data):
        if cls.static_key in data:
            return True
        else:
            return False
