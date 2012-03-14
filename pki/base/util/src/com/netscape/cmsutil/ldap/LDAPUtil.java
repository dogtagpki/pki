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
package com.netscape.cmsutil.ldap;

import java.io.IOException;
import java.util.ArrayList;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.util.LDIF;
import netscape.ldap.util.LDIFAttributeContent;
import netscape.ldap.util.LDIFContent;
import netscape.ldap.util.LDIFModifyContent;
import netscape.ldap.util.LDIFRecord;

public class LDAPUtil {

    // special chars are *, (, ), \, null
    public static String SPECIAL_CHARS = "*()\\\000";

    /**
     * This method escapes special characters for LDAP filter (RFC 4515).
     * Each special character will be replaced by a backslash followed by
     * 2-digit hex of the ASCII code.
     *
     * @param string string to escape
     * @return escaped string
     */
    public static String escape(String string) {
        StringBuilder sb = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (SPECIAL_CHARS.indexOf(c) >= 0) {
                sb.append('\\');
                if (c < 0x10) sb.append('0'); // make sure it's 2-digit
                sb.append(Integer.toHexString(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static void importLDIF(LDAPConnection conn, String filename, ArrayList<String> errors) throws IOException {
        LDIF ldif = new LDIF(filename);
        while (true) {
            try {
                LDIFRecord record = ldif.nextRecord();
                if (record == null)
                    break;

                String dn = record.getDN();
                LDIFContent content = record.getContent();
                int type = content.getType();
                if (type == LDIFContent.ATTRIBUTE_CONTENT) {
                    LDIFAttributeContent c = (LDIFAttributeContent) content;
                    LDAPAttribute[] attrs = c.getAttributes();
                    LDAPAttributeSet myAttrs = new LDAPAttributeSet();
                    for (int i = 0; i < attrs.length; i++)
                        myAttrs.add(attrs[i]);
                    LDAPEntry entry = new LDAPEntry(dn, myAttrs);
                    try {
                        conn.add(entry);
                    } catch (LDAPException ee) {
                        errors.add("LDAPUtil:importLDIF: exception in adding entry " + dn +
                                ":" + ee.toString() + "\n");
                    }
                } else if (type == LDIFContent.MODIFICATION_CONTENT) {
                    LDIFModifyContent c = (LDIFModifyContent) content;
                    LDAPModification[] mods = c.getModifications();
                    try {
                        conn.modify(dn, mods);
                    } catch (LDAPException ee) {
                        errors.add("LDAPUtil:importLDIF: exception in modifying entry " + dn +
                                ":" + ee.toString());
                    }
                }
            } catch (Exception e) {
                throw new IOException(e.toString());
            }
        }
    }
}
