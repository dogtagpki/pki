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
package com.netscape.management.client.acl;

import java.io.Writer;
import java.io.IOException;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPException;

/**
 * The LDAPWriter class overides the close() method of the
 * CharArrayWriter class to implement an LDAP modify on close.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 8/27/97
 * @see Task
 */
public class LdapWriter extends Writer {
    protected LdapACL acl;
    protected String dn;
    protected StringBuffer buf;

    public LdapWriter(LdapACL _acl, Object _dn) {
        acl = _acl;
        dn = (String)_dn;
        buf = new StringBuffer();
        lock = buf;
    }

    public void close() throws IOException {
        String acival = this.toString();
        String oldval = acl.previousACLValue();
        boolean entry = acl.wasEntryFound();
        LDAPConnection ldc = null;

        try {
            ldc = acl.newConnection();

            if (acival.length() != 0) {
                // add new value
                LDAPAttribute attr = new LDAPAttribute("aci", acival);
                ldc.modify(dn,
                        new LDAPModification(LDAPModification.ADD, attr));
            }

            if (entry) {
                // remove previous value, if any
                LDAPAttribute attr = new LDAPAttribute("aci", oldval);
                ldc.modify(dn,
                        new LDAPModification(LDAPModification.DELETE,
                        attr));
            }

            ldc.disconnect();
        } catch (LDAPException le) {
            // DT - we can only throw a subclass of IOException, since close()
            // throws IOException...sheesh

            throw new IOException(LdapACL.checkLDAPError(le));
        }
        finally { if (ldc != null && ldc.isConnected()) {
                try {
                    ldc.disconnect();
                } catch (Exception e) {}
            }

        }
    }

    /**
      * Write a single character.
      */
    public void write(int c) {
        buf.append((char) c);
    }

    /**
      * Write a portion of an array of characters.
      *
      * @param  cbuf  Array of characters
      * @param  off   Offset from which to start writing characters
      * @param  len   Number of characters to write
      */
    public void write(char cbuf[], int off, int len) {
        buf.append(cbuf, off, len);
    }

    /**
      * Write a string.
      */
    public void write(String str) {
        buf.append(str);
    }

    /**
      * Write a portion of a string.
      *
      * @param  str  String to be written
      * @param  off  Offset from which to start writing characters
      * @param  len  Number of characters to write
      */
    public void write(String str, int off, int len) {
        char cbuf[] = new char[len];
        str.getChars(off, len, cbuf, 0);
        buf.append(cbuf);
    }

    /**
      * Return the buffer's current value as a string.
      */
    public String toString() {
        return buf.toString();
    }

    /**
      * Return the string buffer itself.
      */
    public StringBuffer getBuffer() {
        return buf;
    }

    /**
      * Flush the stream.
      */
    public void flush() { }
}
