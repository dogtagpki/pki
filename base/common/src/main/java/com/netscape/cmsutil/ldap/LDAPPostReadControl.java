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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmsutil.ldap;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.ber.stream.BERElement;
import netscape.ldap.ber.stream.BEROctetString;
import netscape.ldap.ber.stream.BERSequence;
import netscape.ldap.ber.stream.BERTag;
import netscape.ldap.client.JDAPBERTagDecoder;

public class LDAPPostReadControl extends LDAPControl {

    private static final long serialVersionUID = -3988578305868188089L;

    public final static String OID_POSTREAD = "1.3.6.1.1.13.2";

    private LDAPEntry entry = null;

    static {
        try {
            register(OID_POSTREAD, LDAPPostReadControl.class);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    /**
     * Response control constructor.
     *
     * This is called automatically by response processing code,
     * should not need to be called by user.
     */
    public LDAPPostReadControl(String oid, boolean critical, byte[] value)
            throws LDAPException, IOException {
        super(OID_POSTREAD, critical, value);
        if (!oid.equals(OID_POSTREAD)) {
            throw new LDAPException(
                "oid must be LDAPPostReadControl.OID_POSTREAD",
                LDAPException.PARAM_ERROR);
        }

        ByteArrayInputStream in = new ByteArrayInputStream(value);
        int[] numRead = new int[1];
        BERTag tag = (BERTag)
            BERElement.getElement(new JDAPBERTagDecoder(), in, numRead);
        BERSequence seq = (BERSequence)tag.getValue();

        BEROctetString name = (BEROctetString)seq.elementAt(0);
        byte buf[] = name.getValue();
        String dn = null;
        if (buf != null)
            dn = new String(buf, "UTF8");

        BERSequence attrs = (BERSequence)seq.elementAt(1);
        LDAPAttributeSet attrSet = new LDAPAttributeSet();
        for (int i = 0; i < attrs.size(); i++) {
            attrSet.add(new LDAPAttribute(attrs.elementAt(i)));
        }

        entry = new LDAPEntry(dn, attrSet);
    }

    /**
     * Request control constructor.
     */
    public LDAPPostReadControl(boolean critical, String[] attrs) {
        super(OID_POSTREAD, critical, null);
        BERSequence ber_attrs = new BERSequence();
        for (int i = 0; i < attrs.length; i++) {
            ber_attrs.addElement(new BEROctetString(attrs[i]));
        }
        m_value = flattenBER(ber_attrs);
    }

    /**
     * Get the entry from the control.
     *
     * Returns null if constructed as a request control.
     */
    public LDAPEntry getEntry() {
        return entry;
    }
};
