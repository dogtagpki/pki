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
import netscape.ldap.*;

/**
 * An OutputStream that writes to an LDAP data source.
 *
 * @author  ahakim@netscape.com
 */
public class LDAPOutputStream extends ByteArrayOutputStream {
    private LDAPConnection _ldc;
    private String _dn;
    private String _attribute;
    private ResourceSet _resource;


    /**
     * Creates an input file stream to read from the specified file descriptor.
     *
     * @param ldc        the ldap connection to be used
     * @param dn         the DN where data is stored
     * @param attribute  the attribute in the DN where data is stored
     */
    public LDAPOutputStream(LDAPConnection ldc, String dn,
            String attribute) {
        super();
        _ldc = ldc;
        _dn = dn;
        _attribute = attribute;
        _resource = new ResourceSet("com.netscape.management.client.util.default");
    }

    // not currently used...
    //protected void clear() throws LDAPException
    //{
    //	LDAPAttribute attribute = new LDAPAttribute(_attribute);
    //	LDAPModification modification = new LDAPModification(LDAPModification.DELETE, attribute);
    //	_ldc.modify(_dn, modification);
    //}

    /**
     * Deletes the entry where the data is stored.
     *
     * @exception LDAPException
     */
    public void delete() throws LDAPException {
        _ldc.delete(_dn);
    }

    private void modify() throws LDAPException {
        LDAPAttribute attr =
                new LDAPAttribute(_attribute, new String(buf, 0, count));
        LDAPModification modification =
                new LDAPModification(LDAPModification.REPLACE, attr);
        _ldc.modify(_dn, modification);
    }

    /**
      * Commits changes to LDAP.
      *
      * @exception IOException
      */
    public void flush() throws IOException {
        super.flush();
        try {
            modify();
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
                throw new IOException(
                        _resource.getString("error", "CannotModify1") +
                        " " + e);

            default:
                throw new IOException(
                        _resource.getString("error", "CannotModify2") +
                        " " + e);
            }
        }
    }

    /**
      * Closes the stream.
      *
      * @exception IOException
      */
    public void close() throws IOException {
        flush();
        super.close();
    }
}
