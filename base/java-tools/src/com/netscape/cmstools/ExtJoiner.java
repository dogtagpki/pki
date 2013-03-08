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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.FileInputStream;
import java.io.IOException;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

import com.netscape.cmsutil.util.Utils;

/**
 * This program joins a sequence of extensions together
 * so that the final output can be used in configuration
 * wizard for specifing extra extensions in default
 * certificates (i.e. CA certificate, SSL certificate).
 *
 * Usage:
 *
 * <pre>
 *  ExtJoiner \
 *    &lt;ext_file0&gt; &lt;ext_file1&gt; ... &lt;ext_fileN&gt;
 *
 *  where,
 *    &lt;ext_file&gt; is a file that has the base64
 *    encoded DER encoding of an X509 Extension
 *
 *  ExtensionSequence ::= SEQUENCE OF Extension;
 *
 *  0 30  142: SEQUENCE {
 *  3 30   69:   SEQUENCE {
 *  5 06    3:     OBJECT IDENTIFIER issuerAltName (2 5 29 18)
 * 10 04   62:     OCTET STRING
 *           :       30 3C 82 01 61 82 01 61 A4 10 30 0E 31 0C 30 0A
 *           :       06 03 55 04 03 13 03 64 73 61 87 04 01 01 01 01
 *           :       86 01 61 81 14 74 68 6F 6D 61 73 6B 40 6E 65 74
 *           :       73 63 61 70 65 2E 63 6F 6D 88 03 29 01 01
 *           :     }
 * 74 30   69:   SEQUENCE {
 * 76 06    3:     OBJECT IDENTIFIER subjectAltName (2 5 29 17)
 * 81 04   62:     OCTET STRING
 *           :       30 3C 82 01 61 82 01 61 A4 10 30 0E 31 0C 30 0A
 *           :       06 03 55 04 03 13 03 64 73 61 87 04 01 01 01 01
 *           :       86 01 61 81 14 74 68 6F 6D 61 73 6B 40 6E 65 74
 *           :       73 63 61 70 65 2E 63 6F 6D 88 03 29 01 01
 *           :     }
 *           :   }
 * </pre>
 *
 * @version $Revision$, $Date$
 */
public class ExtJoiner {

    public static void main(String args[]) {
        try (DerOutputStream out = new DerOutputStream()) {
            if (args.length == 0) {
                System.out.println("Usage:  ExtJoiner <ext_file0> <ext_file1> ... <ext_fileN>");
                System.exit(0);
            }
            DerValue exts[] = new DerValue[args.length];

            for (int i = 0; i < args.length; i++) {
                byte data[] = getFileData(args[i]);

                exts[i] = new DerValue(data);
            }

            out.putSequence(exts);
            System.out.println(Utils.base64encode(out.toByteArray()));
        } catch (IOException e) {
            System.out.println(e.toString());
        }
    }

    public static byte[] getFileData(String fileName)
            throws IOException {
        FileInputStream fis = new FileInputStream(fileName);

        byte data[] = null;
        try {
            data = new byte[fis.available()];
            fis.read(data);
        } finally {
            if (fis != null)
                fis.close();
        }
        return Utils.base64decode(new String(data));
    }
}
