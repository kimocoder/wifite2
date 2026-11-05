import errno
import unittest
from unittest.mock import patch

from wifite.attack.portal.server import PortalServer


class TestPortalPortFallback(unittest.TestCase):
    def _start(self, busy_ports):
        calls = []

        class FakeHTTPServer:
            def __init__(self, addr, handler):
                port = addr[1]
                calls.append(port)
                if port in busy_ports:
                    raise OSError(errno.EADDRINUSE, 'Address already in use')
                self.server_address = (addr[0], 8080 if port == 0 else port)

            def serve_forever(self):
                pass

        server = PortalServer(port=80)
        with patch('wifite.attack.portal.server.ThreadingHTTPServer', FakeHTTPServer), \
                patch('wifite.attack.portal.server.time.sleep'):
            ok = server.start()
        return ok, server, calls

    def test_busy_default_port_falls_back(self):
        ok, server, calls = self._start(busy_ports={80})
        self.assertTrue(ok)
        self.assertEqual(server.port, 8080)
        self.assertEqual(calls, [80, 8080])

    def test_free_default_port_no_fallback(self):
        ok, server, calls = self._start(busy_ports=set())
        self.assertTrue(ok)
        self.assertEqual(server.port, 80)
        self.assertEqual(calls, [80])

    def test_all_named_ports_busy_uses_os_assigned_port(self):
        ok, server, calls = self._start(busy_ports={80, 8080, 8081, 8888, 8000})
        self.assertTrue(ok)
        self.assertEqual(calls[-1], 0)
        self.assertEqual(server.port, 8080)  # fake assigns 8080 for port 0

    def test_non_eaddrinuse_error_fails(self):
        class FakeHTTPServer:
            def __init__(self, addr, handler):
                raise OSError(errno.EACCES, 'Permission denied')

        server = PortalServer(port=80)
        with patch('wifite.attack.portal.server.ThreadingHTTPServer', FakeHTTPServer), \
                patch('wifite.attack.portal.server.time.sleep'):
            self.assertFalse(server.start())


if __name__ == '__main__':
    unittest.main()
