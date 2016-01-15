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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

import unittest

import pki
import requests
import json


class TestHTTPError(requests.exceptions.HTTPError):
    def __init__(self, body):
        super(TestHTTPError, self).__init__()
        self.response = requests.Response()
        self.response._content = body
        self.response.encoding = 'utf-8'


class PKITests(unittest.TestCase):
    def test_handle_exceptions(self):

        @pki.handle_exceptions()
        def raiser(body):
            raise TestHTTPError(body)

        body = json.dumps({
            'Message': 'message',
            'Code': 42,
            'ClassName': 'com.netscape.certsrv.base.BadRequestException',
            'Attributes': {
                'Attribute': [],
            },
        }).encode('utf-8')

        with self.assertRaises(pki.BadRequestException) as e:
            raiser(body)

        self.assertEqual(e.exception.message, 'message')
        self.assertEqual(e.exception.code, 42)
        self.assertEqual(
            e.exception.ClassName,
            'com.netscape.certsrv.base.BadRequestException'
        )

        body = json.dumps({
            'Message': u'messag€ with non-äscii',
            'Code': 42,
            'ClassName': 'com.netscape.certsrv.base.BadRequestException',
            'Attributes': {
                'Attribute': [],
            },
        }).encode('utf-8')

        with self.assertRaises(pki.BadRequestException) as e:
            raiser(body)

        self.assertEqual(e.exception.message, u'messag€ with non-äscii')
        self.assertEqual(e.exception.code, 42)
        self.assertEqual(
            e.exception.ClassName,
            'com.netscape.certsrv.base.BadRequestException'
        )

        with self.assertRaises(TestHTTPError) as e:
            raiser(b'no json body')


if __name__ == '__main__':
    unittest.main()
