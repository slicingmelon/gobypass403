import socket

RESP_BODY = b"test broken header"
RESP = b"\r\n".join([
    b"HTTP/1.1 200 OK",
    b"X-Header-OK: okheader",
    b"X-Bro\nken-Header: broken",
    b"Content-Type: text/plain",
    b"Content-Length: " + str(len(RESP_BODY)).encode(),
    b"Connection: close",
    b"",
    RESP_BODY
])

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 5555))
        s.listen(128)
        s.settimeout(0.5)  # <-- key: periodically wake from accept()
        print("listening on :5555 (Ctrl+C to stop)")
        try:
            while True:
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue  # loop back, allows KeyboardInterrupt to be delivered
                with conn:
                    try:
                        _ = conn.recv(4096)
                    except Exception:
                        pass
                    try:
                        conn.sendall(RESP)
                    except Exception:
                        pass
        except KeyboardInterrupt:
            print("\nshutting down...")

if __name__ == "__main__":
    main()
