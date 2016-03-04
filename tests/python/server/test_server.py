# -*- coding: utf-8 -*-
# Authors:
#     Christian Heimes <cheimes@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

import unittest

from pki.server import PKISubsystem, PKIInstance


class PKIServerTests(unittest.TestCase):
    def test_instance_ordering(self):
        ca = PKIInstance('ca')
        ca9 = PKIInstance('ca', 9)
        kra = PKIInstance('kra')
        instances = [kra, ca, ca9]
        self.assertEqual(sorted(instances), [ca9, ca, kra])
        self.assertEqual(sorted(instances, reverse=True), [kra, ca, ca9])
        self.assertTrue(ca == ca)
        self.assertFalse(ca != ca)
        self.assertFalse(ca == ca9)
        self.assertTrue(ca != ca9)
        d = {ca: 1, ca9: 2}
        self.assertEqual(sorted(d), [ca9, ca])
        d.pop(ca9)
        self.assertEqual(sorted(d), [ca])
        self.assertIn(ca, d)
        self.assertNotIn(ca9, d)

    def test_subsystem(self):
        ca = PKIInstance('ca')
        kra = PKIInstance('kra')
        casub = PKISubsystem(ca, 'ca sub')
        krasub = PKISubsystem(kra, 'kra sub')
        subs = [casub, krasub]
        self.assertEqual(sorted(subs), [casub, krasub])
        self.assertEqual(sorted(subs, reverse=True), [krasub, casub])
        self.assertTrue(casub == casub)
        self.assertFalse(casub != casub)
        self.assertFalse(casub == krasub)
        self.assertTrue(casub != krasub)
        self.assertFalse(ca == casub)
        self.assertTrue(ca != casub)
        d = {casub: 1, krasub: 2}
        self.assertEqual(sorted(d), [casub, krasub])
        self.assertIn(casub, d)
        d.pop(casub)
        self.assertNotIn(casub, d)


if __name__ == '__main__':
    unittest.main()
