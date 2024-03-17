/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/

package com.netscape.management.client.util;

import java.io.*;
import java.util.*;
import netscape.ldap.*;

/**
 * An InputStream that reads from an LDAP data source.
 *
 * @author  ahakim@netscape.com
 */
public class LDAPInputStream extends ByteArrayInputStream {
    private LDAPConnection _ldc;
    private String _attrName;
    private String _dn;

    /**
     * Creates an input file stream to read from the specified file descriptor.
     *
     * @param ldc       the ldap connection to be used
     * @param dn        the DN where data is stored
     * @param attrName  the attribute in the DN where data is stored
     */
    public LDAPInputStream(LDAPConnection ldc, String dn, String attrName) {
        super(new byte[1]);
        _ldc = ldc;
        _dn = dn;
        _attrName = attrName;
        pos = 0;
        count = 0;
        load();
    }

    private void load() {
        try {
            LDAPEntry entry = null;
            entry = _ldc.read(_dn, new String[]{ _attrName });
            if (entry != null) {
                LDAPAttribute attribute = entry.getAttribute(_attrName);
                if (attribute != null) {
                    Enumeration e = attribute.getByteValues();
                    if (e.hasMoreElements()) {
                        buf = (byte[]) e.nextElement();
                        pos = 0;
                        count = buf.length;
                    }
                }
            }
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
                break;

            default:
                Debug.println("Cannot read user preference: " + _dn);
                break;
            }
        }
    }
}
