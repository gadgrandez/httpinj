from common import *

class payload(CommonPayload):

    @classmethod
    def http_payload(cls):
        header = "HTTP/1.1 302 Found\r\nServer: httpinj\r\nLocation: http://www.google.com\r\n\r\n"

        return header + cls.content

