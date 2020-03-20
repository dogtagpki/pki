// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmsutil.crypto;

import org.junit.Assert;
import org.junit.Test;

/**
 * Key ID encoder and decoder validation.
 *
 * Key ID in NSS database is a 20 byte array. The key ID is
 * stored in CS.cfg as a signed, variable-length, hexadecimal
 * number.
 *
 * This test verifies that Key ID can be encoded and
 * decoded correctly using the following methods:
 *  - CryptoUtil.encodeKeyID()
 *  - CryptoUtil.decodeKeyID()
 *
 * The test is performed against a set of valid data that
 * covers the entire range of 20 byte array, and some invalid
 * data as well.
 */
public class KeyIDCodecTest {

    // data #1: zero
    String DATA1_HEX = "0";

    // 0000000000000000000000000000000000000000
    byte[] DATA1_BYTES = new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };

    // data #2: small positive number (with leading 0x00)
    String DATA2_HEX = "18604db6c7a073ff08338650";

    // 000000000000000018604db6c7a073ff08338650
    byte[] DATA2_BYTES = new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x18, (byte)0x60, (byte)0x4d, (byte)0xb6,
            (byte)0xc7, (byte)0xa0, (byte)0x73, (byte)0xff,
            (byte)0x08, (byte)0x33, (byte)0x86, (byte)0x50
    };

    // data #3: large positive number
    String DATA3_HEX = "446ed35d7e811e7f73d0d1f220afc60083deba74";

    // 446ed35d7e811e7f73d0d1f220afc60083deba74
    byte[] DATA3_BYTES = new byte[] {
            (byte)0x44, (byte)0x6e, (byte)0xd3, (byte)0x5d,
            (byte)0x7e, (byte)0x81, (byte)0x1e, (byte)0x7f,
            (byte)0x73, (byte)0xd0, (byte)0xd1, (byte)0xf2,
            (byte)0x20, (byte)0xaf, (byte)0xc6, (byte)0x00,
            (byte)0x83, (byte)0xde, (byte)0xba, (byte)0x74
    };

    // data #4: highest 20-byte number
    String DATA4_HEX = "7fffffffffffffffffffffffffffffffffffffff";

    // 7fffffffffffffffffffffffffffffffffffffff
    byte[] DATA4_BYTES = new byte[] {
            (byte)0x7f, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff
    };

    // data #5: negative one
    String DATA5_HEX = "-1";

    // ffffffffffffffffffffffffffffffffffffffff
    byte[] DATA5_BYTES = new byte[] {
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff
    };

    // data 6: small negative number (with leading 0xff)
    String DATA6_HEX = "-314bd3fd90753fe3687d358d";

    // ffffffffffffffffffffceb42c026f8ac01c9782ca73
    byte[] DATA6_BYTES = new byte[] {
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
            (byte)0xce, (byte)0xb4, (byte)0x2c, (byte)0x02,
            (byte)0x6f, (byte)0x8a, (byte)0xc0, (byte)0x1c,
            (byte)0x97, (byte)0x82, (byte)0xca, (byte)0x73
    };

    // data #7: large negative number
    String DATA7_HEX = "-16e096b561838ac32855acc30a09e6a2d9adc120";

    // e91f694a9e7c753cd7aa533cf5f6195d26523ee0
    byte[] DATA7_BYTES = new byte[] {
            (byte)0xe9, (byte)0x1f, (byte)0x69, (byte)0x4a,
            (byte)0x9e, (byte)0x7c, (byte)0x75, (byte)0x3c,
            (byte)0xd7, (byte)0xaa, (byte)0x53, (byte)0x3c,
            (byte)0xf5, (byte)0xf6, (byte)0x19, (byte)0x5d,
            (byte)0x26, (byte)0x52, (byte)0x3e, (byte)0xe0
    };

    // data #8: lowest 20-byte number
    String DATA8_HEX = "-8000000000000000000000000000000000000000";

    // 8000000000000000000000000000000000000000
    byte[] DATA8_BYTES = new byte[] {
            (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
    };

    Object[][] TEST_DATA = {
            new Object[] { DATA1_BYTES, DATA1_HEX },
            new Object[] { DATA2_BYTES, DATA2_HEX },
            new Object[] { DATA3_BYTES, DATA3_HEX },
            new Object[] { DATA4_BYTES, DATA4_HEX },
            new Object[] { DATA5_BYTES, DATA5_HEX },
            new Object[] { DATA6_BYTES, DATA6_HEX },
            new Object[] { DATA7_BYTES, DATA7_HEX },
            new Object[] { DATA8_BYTES, DATA8_HEX }
    };

    @Test
    public void testEncoder() throws Exception {

        System.out.println("Testing Key ID encoder with valid data:");

        for (int i = 0; i < TEST_DATA.length; i++) {
            System.out.println(" - data #" + (i + 1));

            byte[] bytes = (byte[])TEST_DATA[i][0];
            String hex = (String)TEST_DATA[i][1];

            String result = CryptoUtil.encodeKeyID(bytes);
            Assert.assertEquals(hex, result);
        }

        System.out.println("Testing Key ID encoder with invalid data:");

        try {
            System.out.println(" - null data");
            CryptoUtil.encodeKeyID(null);
            Assert.fail("should throw NullPointerException");
        } catch (Exception e) {
            Assert.assertTrue(e instanceof NullPointerException);
        }

        try {
            System.out.println(" - empty data");
            CryptoUtil.encodeKeyID(new byte[] {});
            Assert.fail("should throw IllegalArgumentException");
        } catch (Exception e) {
            Assert.assertTrue(e instanceof IllegalArgumentException);
        }

        try {
            System.out.println(" - incorrect length data");
            CryptoUtil.encodeKeyID(new byte[] { (byte)0x24, (byte)0xac });
            Assert.fail("should throw IllegalArgumentException");
        } catch (Exception e) {
            Assert.assertTrue(e instanceof IllegalArgumentException);
        }
    }

    @Test
    public void testDecoder() throws Exception {

        System.out.println("Testing Key ID decoder with valid data:");

        for (int i = 0; i < TEST_DATA.length; i++) {
            System.out.println(" - data #" + (i + 1));

            byte[] bytes = (byte[])TEST_DATA[i][0];
            String hex = (String)TEST_DATA[i][1];

            byte[] result = CryptoUtil.decodeKeyID(hex);
            Assert.assertArrayEquals(bytes, result);
        }

        System.out.println("Testing Key ID decoder with invalid data:");

        try {
            System.out.println(" - null data");
            CryptoUtil.decodeKeyID(null);
            Assert.fail("should throw NullPointerException");
        } catch (Exception e) {
            Assert.assertTrue(e instanceof NullPointerException);
        }

        try {
            System.out.println(" - empty data");
            CryptoUtil.decodeKeyID("");
            Assert.fail("should throw IllegalArgumentException");
        } catch (Exception e) {
            Assert.assertTrue(e instanceof IllegalArgumentException);
        }

        try {
            System.out.println(" - incorrect length data");
            CryptoUtil.decodeKeyID("ffffffffffffffffffffffffffffffffffffffffff");
            Assert.fail("should throw IllegalArgumentException");
        } catch (Exception e) {
            Assert.assertTrue(e instanceof IllegalArgumentException);
        }

        try {
            System.out.println(" - garbage data");
            CryptoUtil.decodeKeyID("garbage");
            Assert.fail("should throw NumberFormatException");
        } catch (Exception e) {
            Assert.assertTrue(e instanceof NumberFormatException);
        }
    }
}
