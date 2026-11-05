#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Dependency check imports must match the consolidated tool modules."""

import sys
import unittest

sys.path.insert(0, '..')


class DependencyImportTest(unittest.TestCase):
    def test_hcxdumptool_class_is_in_its_own_module(self):
        from wifite.tools.hashcat import Hashcat, HcxPcapngTool
        from wifite.tools.hcxdumptool import HcxDumpTool
        from wifite.tools.dependency import Dependency

        assert issubclass(HcxDumpTool, Dependency)
        assert issubclass(Hashcat, Dependency)
        assert issubclass(HcxPcapngTool, Dependency)

    def test_dependency_check_resolves_all_imports(self):
        from wifite.tools.dependency import Dependency
        # Must not raise ImportError for the consolidated hcxdumptool class.
        Dependency.run_dependency_check()


if __name__ == '__main__':
    unittest.main()