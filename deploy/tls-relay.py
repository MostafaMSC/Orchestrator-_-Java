#!/usr/bin/env python3
"""
Terminate TLS on loopback so one ADSS exchange can be read in the clear.

ADSS reports a refusal in HTTP response headers with an empty body, and the
Client SDK throws a NullPointerException on the missing SOAP body before the
application can see them. Over plaintext tcpdump is enough; over TLS this relay
is the way in.

    python3 deploy/tls-relay.py sign-direct-stg.techsource.iq

Then point signing.gateway.url at http://127.0.0.1:18777/adss/signing/hdsi,
send one request, and read /tmp/relay.log. Put the real URL back afterwards.

Nothing is sent anywhere it was not already going: the upstream host is the one
named on the command line, the Host header is rewritten to it so a proxy in
front still routes correctly, and only loopback is listened on. The response is
logged verbatim, so the log holds whatever the response held - treat it as
sensitive and delete it when done.
"""
import re
import socket
import ssl
import sys
import threading

UP_HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
UP_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 443
LISTEN_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 18777
LOG_PATH = "/tmp/relay.log"


def handle(client, log):
    try:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = client.recv(4096)
            if not chunk:
                return
            head += chunk
        split = head.find(b"\r\n\r\n")
        lines = head[:split + 4].split(b"\r\n")
        body = head[split + 4:]

        length = 0
        for line in lines:
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1].strip())

        # The gateway URL names the relay, so the upstream vhost has to be
        # restored or a reverse proxy in front of ADSS will not route it.
        lines = [l for l in lines if not l.lower().startswith(b"host:")]
        lines.insert(1, b"Host: " + UP_HOST.encode())

        context = ssl._create_unverified_context()
        upstream = context.wrap_socket(
            socket.create_connection((UP_HOST, UP_PORT), 30), server_hostname=UP_HOST)
        upstream.sendall(b"\r\n".join(lines) + body)

        remaining = length - len(body)
        while remaining > 0:
            chunk = client.recv(min(65536, remaining))
            if not chunk:
                break
            upstream.sendall(chunk)
            remaining -= len(chunk)

        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            log.write(chunk)
            client.sendall(chunk)
    except Exception as error:
        log.write(b"RELAY ERROR: " + str(error).encode() + b"\n")
    finally:
        try:
            client.close()
        except Exception:
            pass


def visible_text(raw):
    """An HTML error body with the markup stripped, which is where a WAF names
    itself. Without this a block page is easily mistaken for ADSS refusing."""
    text = raw.decode("utf-8", "replace")
    text = re.sub(r"(?s)<(style|script).*?</\1>", " ", text)
    text = re.sub(r"data:image/[^)\"']+", " ", text)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


def main():
    log = open(LOG_PATH, "wb", 0)
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", LISTEN_PORT))
    server.listen(5)
    print("relaying 127.0.0.1:%d -> %s:%d, logging to %s"
          % (LISTEN_PORT, UP_HOST, UP_PORT, LOG_PATH))
    print("Ctrl-C to stop; the response summary is printed on exit.")
    try:
        while True:
            connection, _ = server.accept()
            threading.Thread(target=handle, args=(connection, log), daemon=True).start()
    except KeyboardInterrupt:
        log.close()
        with open(LOG_PATH, "rb") as captured:
            raw = captured.read()
        print("\n--- response headers ---")
        for line in raw.split(b"\r\n\r\n")[0].decode("utf-8", "replace").splitlines():
            print("  " + line)
        if b"<html" in raw.lower():
            print("\n--- HTML body, markup stripped ---")
            print("  " + visible_text(raw)[:800])


if __name__ == "__main__":
    main()
