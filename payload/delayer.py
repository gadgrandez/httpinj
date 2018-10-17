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
    <h1>Loading...</h1>
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
    def hash(cls, since, expire):
        return str(zlib.crc32((cls.hash_secret + str(since) + str(expire)).encode()) & 0xffffffff)

    @classmethod
    def bypass_generate(cls):
        ts = int(time.time())
        time_since = ts + cls.load_delay
        time_expire = ts + cls.bypass_ttl
        return "%s-%s-%s" % (time_since, time_expire, cls.hash(time_since, time_expire))

    @classmethod
    def bypass_validate(cls, data):
        m = re.search(cls.bypass_name + '=(\d{10})-(\d{10})-(\d{1,10})[;\s]', data)
        if m and m.group(1) and m.group(2) and m.group(3):
            time_since = m.group(1)
            time_expire = m.group(2)
            hash = m.group(3)
            if cls.hash(time_since, time_expire) == hash:
                # print "bypass window: %s~%s" % (time_since, time_expire)
                now = time.time()
                if int(time_since) <= now < int(time_expire):
                    # print "bypassed"
                    return True
                else:
                    # print "%s out of bypass window" % now
                    return False

            else:
                # print "bad hash"
                return False
        else:
            return False
