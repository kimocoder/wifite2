import sys
import unittest

from wifite.tools.dnsmasq import Dnsmasq
from wifite.tools.hostapd import Hostapd
from wifite.util.credential_validator import CredentialValidator
from wifite.util.interface_manager import InterfaceManager


class TestDestructorSurvivesInterpreterShutdown(unittest.TestCase):
    """__del__ must not import: during interpreter shutdown an import
    fails with "sys.meta_path is None", which surfaced as "Exception
    ignored while calling deallocator" tracebacks after Evil Twin runs.
    """

    def _call_del_during_shutdown(self, obj):
        contextlib_module = sys.modules.pop('contextlib', None)
        meta_path = sys.meta_path
        sys.meta_path = None
        try:
            obj.__del__()
        finally:
            sys.meta_path = meta_path
            if contextlib_module is not None:
                sys.modules['contextlib'] = contextlib_module

    def test_dnsmasq_destructor_needs_no_import(self):
        self._call_del_during_shutdown(Dnsmasq('wlan9'))

    def test_hostapd_destructor_needs_no_import(self):
        self._call_del_during_shutdown(Hostapd('wlan9', 'fixture', 1))

    def test_credential_validator_destructor_needs_no_import(self):
        validator = CredentialValidator('wlan9', '00:11:22:33:44:55', 6)
        self._call_del_during_shutdown(validator)

    def test_interface_manager_destructor_needs_no_import(self):
        self._call_del_during_shutdown(InterfaceManager())


if __name__ == '__main__':
    unittest.main()
