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
 * Convenient class to construct a SSL3 cipher list.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 * @see com.netscape.admin.certsrv.security.SSL3CipherPreference
 */
public final class SSL3CipherSet implements ICipherConstants,
IAbstractCipherSet {

    Vector abstractCipherList = new Vector();
    String title;

    final boolean defaultOn = true;

    /**
     * Create a SSL2 cipher set
     *
     * @param isDomestic  show domestic ssl3 ciphers if true
     * @param hasFortezza show fortezza ciphers if true
     *
     */
    public SSL3CipherSet(boolean isDomestic, boolean hasFortezza) {
        CipherResourceSet resource = new CipherResourceSet();

        abstractCipherList.addElement( new AbstractCipher(
                resource.getString("ssl3", "RSA_RC4_40_MD5"),
                RSA_RC4_40_MD5 , defaultOn));
        abstractCipherList.addElement( new AbstractCipher(
                resource.getString("ssl3", "RSA_RC2_40_MD5"),
                RSA_RC2_40_MD5 , defaultOn));

        abstractCipherList.addElement( new AbstractCipher(
                resource.getString("ssl3", "TLS_RSA_DES_SHA"),
                TLS_RSA_DES_SHA, defaultOn));

        abstractCipherList.addElement( new AbstractCipher(
                resource.getString("ssl3", "TLS_RSA_RC4_SHA"),
                TLS_RSA_RC4_SHA, defaultOn));

        if (isDomestic) {
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl3", "RSA_DES_SHA"),
                    RSA_DES_SHA , defaultOn));
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl3", "RSA_RC4_128_MD5"),
                    RSA_RC4_128_MD5 , defaultOn));
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl3", "RSA_3DES_SHA"),
                    RSA_3DES_SHA , defaultOn));

            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl3", "RSA_FIPS_DES_SHA"),
                    RSA_FIPS_DES_SHA , !defaultOn));
            abstractCipherList.addElement( new AbstractCipher(
                    resource.getString("ssl3", "RSA_FIPS_3DES_SHA"),
                    RSA_FIPS_3DES_SHA , !defaultOn));

            if (hasFortezza) {
                abstractCipherList.addElement( new AbstractCipher(
                        resource.getString("ssl3", "FORTEZZA"),
                        FORTEZZA , defaultOn));
                abstractCipherList.addElement( new AbstractCipher(
                        resource.getString("ssl3", "FORTEZZA_RC4_128_SHA"),
                        FORTEZZA_RC4_128_SHA, defaultOn));
                abstractCipherList.addElement( new AbstractCipher(
                        resource.getString("ssl3", "FORTEZZA_NULL"),
                        FORTEZZA_NULL , !defaultOn));
            }

        }

        abstractCipherList.addElement( new AbstractCipher(
                resource.getString("ssl3", "RSA_NULL_MD5"),
                RSA_NULL_MD5 , !defaultOn));

        title = resource.getString("ssl3", "CipherTitle");
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
