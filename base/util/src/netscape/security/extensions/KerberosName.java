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
package netscape.security.extensions;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Vector;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * This represents a KerberosName as defined in
 * RFC 1510.
 *
 * KerberosName ::= SEQUENCE {
 * realm [0] Realm,
 * principalName [1] CertPrincipalName -- defined above
 * }
 *
 * CertPrincipalName ::= SEQUENCE {
 * name-type[0] INTEGER,
 * name-string[1] SEQUENCE OF UTF8String
 * }
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class KerberosName {

    public static final int OID[] = { 1, 3, 6, 1, 5, 2, 2 };
    public static final ObjectIdentifier KRB5_PRINCIPAL_NAME = new
            ObjectIdentifier(OID);

    private String m_realm = null;
    private int m_name_type = 0;
    private Vector<String> m_name_strings = null;

    public KerberosName(String realm, int name_type, Vector<String> name_strings) {
        m_realm = realm;
        m_name_type = name_type;
        m_name_strings = name_strings;
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {

        try (DerOutputStream seq = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();
            DerOutputStream realm = new DerOutputStream();
            realm.putGeneralString(m_realm);
            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                    true, (byte) 0), realm);

            DerOutputStream seq1 = new DerOutputStream();
            DerOutputStream tmp1 = new DerOutputStream();
            DerOutputStream name_type = new DerOutputStream();
            name_type.putInteger(new BigInt(m_name_type));
            tmp1.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                    true, (byte) 0), name_type);

            DerOutputStream name_strings = new DerOutputStream();
            DerOutputStream name_string = new DerOutputStream();
            for (int i = 0; i < m_name_strings.size(); i++) {
                name_string.putGeneralString(m_name_strings.elementAt(i));
            }
            name_strings.write(DerValue.tag_SequenceOf, name_string);
            tmp1.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                    true, (byte) 1), name_strings);
            seq1.write(DerValue.tag_Sequence, tmp1);
            tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                    true, (byte) 1), seq1);

            seq.write(DerValue.tag_Sequence, tmp);
            out.write(seq.toByteArray());
        }
    }

    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        encode(bos);
        return bos.toByteArray();
    }

    public String toString() {
        String strings = null;
        for (int i = 0; i < m_name_strings.size(); i++) {
            if (strings == null) {
                strings = m_name_strings.elementAt(i);
            } else {
                strings += ",";
                strings += m_name_strings.elementAt(i);
            }
        }
        return "Realm: " + m_realm + " Name Type: " + m_name_type + " Name String(s):" + strings;
    }

    public static void main(String[] argv) {
        Vector<String> strings = new Vector<String>();
        strings.addElement("name");
        KerberosName k = new KerberosName("realm", 0, strings);

        System.out.println(k.toString());
        try {
            FileOutputStream os = new FileOutputStream("/tmp/out.der");
            k.encode(os);
            os.close();
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }
}
