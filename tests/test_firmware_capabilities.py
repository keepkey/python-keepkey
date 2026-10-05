# This file is part of the KeepKey project.
#
# Copyright (C) 2026 KeepKey
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""One test per Features.Capability value.

Each passes when the firmware reports the capability and skips, with the
capability prefix the reports read, when it does not. Release reports learn
what a build lacks from these skips, so the device alone decides; nothing is
declared outside the firmware. Firmware before 7.15.0 reports no list and
every test here passes on version alone (version gates decide there).
"""

import unittest

import common
from keepkeylib import messages_pb2


class TestFirmwareCapabilities(common.KeepKeyTest):
    pass


def _capability_test(name):
    def test(self):
        self.requires_release_capability(name)
    return test


for _value in messages_pb2.Features.Capability.values():
    _enum_name = messages_pb2.Features.Capability.Name(_value)
    if _value == 0:
        continue
    _name = _enum_name[len("CAPABILITY_"):].lower().replace("_", "-")
    setattr(TestFirmwareCapabilities, "test_" + _name.replace("-", "_"),
            _capability_test(_name))


if __name__ == '__main__':
    unittest.main()
