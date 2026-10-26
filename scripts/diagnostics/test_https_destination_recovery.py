#!/usr/bin/env python3
"""Explicit engine integration test. All listeners and upstreams are loopback fixtures.

No account, WireGuard peer, DNS lookup, external request, TUN or installed service
is used. Run: python3 <this file> --core /path/to/mihomo
"""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest


def receive_exact(stream, count):
    result = b""
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError("fixture connection closed")
        result += part
    return result


def socks_request(stream, host, port):
    stream.sendall(b"\x05\x01\x00")
    assert receive_exact(stream, 2) == b"\x05\x00"
    try:
        encoded = socket.inet_pton(socket.AF_INET, host)
        address = b"\x01" + encoded
    except OSError:
        try:
            encoded = socket.inet_pton(socket.AF_INET6, host)
            address = b"\x04" + encoded
        except OSError:
            encoded = host.encode("ascii")
            address = b"\x03" + bytes([len(encoded)]) + encoded
    stream.sendall(b"\x05\x01\x00" + address + struct.pack("!H", port))
    reply = receive_exact(stream, 4)
    assert reply[:2] == b"\x05\x00"
    size = {1: 4, 4: 16}.get(reply[3])
    if size is None:
        size = receive_exact(stream, 1)[0]
    receive_exact(stream, size + 2)


def client_hello(hostname):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ssl.create_default_context().wrap_bio(incoming, outgoing, server_hostname=hostname)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class HttpsDestinationRecoveryEngineTest(unittest.TestCase):
    core = None
    sniffer = None

    def check_destination(self, destination, *, hostname="service.example.invalid", port=443, enabled=True, payload=None):
        observed = queue.Queue()
        upstream = socket.socket()
        upstream.bind(("127.0.0.1", 0))
        upstream.listen()
        upstream.settimeout(5)
        upstream_port = upstream.getsockname()[1]
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        mixed = reservation.getsockname()[1]
        reservation.close()

        def serve():
            try:
                with upstream.accept()[0] as connection:
                    connection.settimeout(4)
                    version, count = receive_exact(connection, 2)
                    assert version == 5
                    receive_exact(connection, count)
                    connection.sendall(b"\x05\x00")
                    header = receive_exact(connection, 4)
                    if header[3] == 1:
                        host = socket.inet_ntop(socket.AF_INET, receive_exact(connection, 4))
                    elif header[3] == 4:
                        host = socket.inet_ntop(socket.AF_INET6, receive_exact(connection, 16))
                    else:
                        host = receive_exact(connection, receive_exact(connection, 1)[0]).decode("ascii")
                    target_port = struct.unpack("!H", receive_exact(connection, 2))[0]
                    observed.put((host, target_port))
                    connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                    connection.recv(65536)
            except Exception as error:
                observed.put(error)

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        with tempfile.TemporaryDirectory(prefix="adapter-tls-fixture-") as directory:
            config = {
                "mixed-port": mixed, "bind-address": "127.0.0.1", "allow-lan": False,
                "ipv6": True, "mode": "rule", "log-level": "silent",
                "tun": {"enable": False}, "dns": {"enable": False},
                "profile": {"store-selected": False, "store-fake-ip": False},
                "proxies": [{"name": "FIXTURE", "type": "socks5", "server": "127.0.0.1", "port": upstream_port}],
                "rules": ["MATCH,FIXTURE"],
            }
            if enabled:
                config["sniffer"] = self.sniffer
            path = Path(directory) / "fixture.json"
            path.write_text(json.dumps(config))
            process = subprocess.Popen([self.core, "-d", directory, "-f", str(path)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while True:
                    try:
                        stream = socket.create_connection(("127.0.0.1", mixed), timeout=0.2)
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("isolated fixture core did not start")
                        time.sleep(0.02)
                with stream:
                    stream.settimeout(5)
                    socks_request(stream, destination, port)
                    stream.sendall(client_hello(hostname) if payload is None else payload)
                    result = observed.get(timeout=5)
                if isinstance(result, Exception):
                    raise result
                return result
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                upstream.close()
                server.join(timeout=1)

    def test_stale_ipv4_is_replaced_by_tls_hostname(self):
        self.assertEqual(("service.example.invalid", 443), self.check_destination("192.0.2.42"))

    def test_stale_ipv6_is_replaced_by_tls_hostname(self):
        self.assertEqual(("service.example.invalid", 443), self.check_destination("2001:db8::42"))

    def test_disabled_baseline_preserves_stale_ip(self):
        self.assertEqual(("192.0.2.42", 443), self.check_destination("192.0.2.42", enabled=False))

    def test_explicit_hostname_is_preserved(self):
        self.assertEqual(("explicit.example.invalid", 443), self.check_destination("explicit.example.invalid"))

    def test_private_literal_is_preserved(self):
        self.assertEqual(("127.0.0.2", 443), self.check_destination("127.0.0.2"))

    def test_other_ports_are_preserved(self):
        self.assertEqual(("192.0.2.42", 9443), self.check_destination("192.0.2.42", port=9443))

    def test_private_ipv6_literal_is_preserved(self):
        self.assertEqual(("::1", 443), self.check_destination("::1"))

    def test_non_tls_payload_is_not_interpreted_as_an_http_hostname(self):
        payload = b"GET / HTTP/1.1\r\nHost: another.example.invalid\r\n\r\n"
        self.assertEqual(("192.0.2.42", 443), self.check_destination("192.0.2.42", payload=payload))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True)
    args, remaining = parser.parse_known_args()
    HttpsDestinationRecoveryEngineTest.core = str(Path(args.core).resolve(strict=True))
    repository = Path(__file__).resolve().parents[2]
    ruby = os.environ.get("ADAPTER_RUBY") or shutil.which("ruby")
    command = [ruby, "-r", str(repository / "daemon/mullvad_adapter"), "-e",
               "puts JSON.generate(MullvadAdapter.allocate.send(:https_destination_recovery_config))"]
    HttpsDestinationRecoveryEngineTest.sniffer = json.loads(subprocess.check_output(command, text=True))
    unittest.main(argv=[__file__, *remaining])
