#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""John must not select the OpenCL format without a usable device."""

import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, '..')

from wifite.tools.john import John

pytestmark = pytest.mark.timeout(30)


class JohnOpenclProbeTest(unittest.TestCase):
    def _get_format(self, formats_output, devices_output=None, devices_error=None):
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if devices_error is not None and '--list=opencl-devices' in argv:
                raise devices_error
            result = MagicMock()
            if '--list=formats' in argv:
                result.stdout = formats_output
                result.stderr = ''
            elif '--list=opencl-devices' in argv:
                result.stdout = devices_output or ''
                result.stderr = ''
            return result

        with patch('wifite.tools.john.subprocess.run', side_effect=fake_run):
            return John._get_format(), calls

    def test_opencl_with_usable_device(self):
        result, calls = self._get_format(
            'wpapsk-opencl wpapsk-cuda wpapsk', 'Platform #0: device 0')

        assert result == 'wpapsk-opencl'
        assert ['john', '--list=opencl-devices'] in calls

    def test_opencl_without_device_falls_back_to_cpu(self):
        result, calls = self._get_format(
            'wpapsk-opencl wpapsk', 'No OpenCL-capable devices found')

        assert result == 'wpapsk'
        assert ['john', '--list=opencl-devices'] in calls

    def test_opencl_probe_error_falls_back_to_cpu(self):
        result, _ = self._get_format(
            'wpapsk-opencl wpapsk', devices_error=OSError('unsupported option'))

        assert result == 'wpapsk'

    def test_cuda_is_used_when_opencl_not_present(self):
        result, calls = self._get_format('wpapsk-cuda wpapsk')

        assert result == 'wpapsk-cuda'
        assert all('--list=opencl-devices' not in call for call in calls)


if __name__ == '__main__':
    unittest.main()