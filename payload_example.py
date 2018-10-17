# Note: This file is execed.
content = """
<html>
<body>
<h1>Please Login!</h1>
</body>
</html>
"""
header = "HTTP/1.1 200 OK\r\nServer: Undefined\r\nRefresh: 5; url=/?bp={bypass}\r\nConnection: close\r\nCache-Control: public, max-age=0\r\nContent-type: text/html\r\nContent-length: %s\r\n\r\n" % len(content)
http_payload = {
	'header': header,
	'content': content
}