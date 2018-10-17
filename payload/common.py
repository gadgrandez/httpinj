class CommonPayload(object):
    bypass_name = "httpinj_bp"
    bypass_ttl = 10
    content = ""
    content_length = len(content)

    @classmethod
    def http_payload(cls):
        header = "HTTP/1.1 200 OK\r\nServer: httpinj\r\nConnection: close\r\nContent-length: %s\r\n\r\n" % (cls.content_length)

        return header + cls.content

    @classmethod
    def bypass_generate(cls):
        return None

    @classmethod
    def bypass_validate(cls, raw):
        return False

