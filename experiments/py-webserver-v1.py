from http.server import HTTPServer, SimpleHTTPRequestHandler
import os
from urllib.parse import urlparse

class CustomHandler(SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_raw_request(self):
        raw_request = self.raw_requestline.decode('utf-8').strip()
        print(f"\n[Raw Request]")
        print(f"{raw_request}")
        print("Headers:")
        for header, value in self.headers.items():
            print(f"{header}: {value}")
        print()

    def do_GET(self):
        # Add debug logging for path parsing
        print(f"\n[Raw Request Path] self.path: {self.path}")
        parsed_path = urlparse(self.path)
        print(f"[URLParse] parsed_path.path: {parsed_path.path}")
        print(f"[Check] Starts with /video/: {parsed_path.path.startswith('/video/')}")

        # Log complete raw request first
        self.log_raw_request()
        print(f"[Request] {self.command} {self.path}")
        print("Headers:")
        for header, value in self.headers.items():
            print(f"  {header}: {value}")

        parsed_path = urlparse(self.path)
        
        # Check if path starts with /video/
        if parsed_path.path.startswith('/video/'):
            x_ip_addr = self.headers.get('X-IP-Addr')
            
            if not x_ip_addr or x_ip_addr.strip() != '127.0.0.1':
                print(f"[Response] 403 Forbidden - Invalid or missing X-IP-Addr: {x_ip_addr}")
                self.send_error(403, "Forbidden - X-IP-Addr header required")
                return
            
            # If we reach here, X-IP-Addr is correct, serve test.mp4
            file_path = os.path.join(os.getcwd(), "test.mp4")
            if os.path.isfile(file_path):
                self.send_response(200)
                self.send_header('Content-type', 'video/mp4')
                self.send_header('Content-Length', os.path.getsize(file_path))
                self.end_headers()
                with open(file_path, 'rb') as f:
                    self.copyfile(f, self.wfile)
            else:
                self.send_error(404, "File not found")
            return

        # For all other paths, use default handler
        try:
            super().do_GET()
        except Exception as e:
            print(f"[Error] {str(e)}")
            self.send_error(500, f"Internal Server Error: {str(e)}")

if __name__ == "__main__":
    server_address = ('', 80)
    httpd = HTTPServer(server_address, CustomHandler)
    print("Server running on port 80...")
    print("Waiting for requests...")
    httpd.serve_forever()