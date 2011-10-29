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
package com.netscape.admin.certsrv.security;

import java.util.Vector;

/**
 *
 * Convenient class to construct a SSL2 cipher list.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 * @see com.netscape.admin.certsrv.security.SSL2CipherPreference
 */
public final class SSL2CipherSet implements ICipherConstants,
IAbstractCipherSet {


    Vector abstractCipherList = new Vector();
    String title;

    final boolean defaultOn = true;

    /**
     * Create a SSL2 cipher set
     *
     * @param isDomestic show domestic ssl2 ciphers if true
     *
     */
    public SSL2CipherSet(boolean isDomestic) {
        CipherResourceSet resource = new CipherResourceSet();

        abstractCipherList.addElement( new AbstractCipher(
                resource.getString("ssl2", "RC4EXPORT"), RC4EXPORT,
                defaultOn));
        abstractCipherList.addElement( new AbstractCipher(
                resource.getString("ssl2", "RC2EXPORT"), RC2EXPORT,
                defaultOn));
        if (isDomestic) {
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl2", "RC4"), RC4 , defaultOn));
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl2", "RC2"), RC2 , defaultOn));
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl2", "DES"), DES , defaultOn));
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl2", "DES3"), DES3 , defaultOn));
        }

        title = resource.getString("ssl2", "CipherTitle");
    }

    /**
      * Return title.
      * For purpose of setting title if cipher is placed in a dialog or TitleBorder
      *
      */
    public String getTitle() {
        return title;
    }

    /**
      * Return cipher list
      *
      */
    public Vector getCipherList() {
        return abstractCipherList;
    }
}
