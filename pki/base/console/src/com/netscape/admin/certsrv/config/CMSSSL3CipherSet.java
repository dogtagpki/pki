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
package com.netscape.admin.certsrv.config;

import com.netscape.admin.certsrv.security.*;
import java.util.*;
import com.netscape.admin.certsrv.*;

/**
 * Constructs a SSL3 cipher suites.
 * 
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CMSSSL3CipherSet implements ICipherConstants, IAbstractCipherSet {
    Vector cipherList = new Vector();
    String title;

    boolean defaultOn = true;

    /**
     * Create a SSL3 cipher set
     * @param isDomestic show all ssl2 ciphers for domestic and export version.
     */
    public CMSSSL3CipherSet(boolean isDomestic, boolean hasFortezza) {
       ResourceBundle resource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL3CIPHERPREF_RC440MD5"),
           RSA_RC4_40_MD5, defaultOn));
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL3CIPHERPREF_RC240MD5"),
           RSA_RC2_40_MD5, defaultOn));
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL3CIPHERPREF_DES56SHA"),
           RSA_DES_SHA, defaultOn));
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL3CIPHERPREF_FIPSDES56SHA"),
           RSA_FIPS_DES_SHA, defaultOn));
       if (isDomestic) {
           cipherList.addElement(
             new AbstractCipher(resource.getString("SSL3CIPHERPREF_RC4128MD5"),
               RSA_RC4_128_MD5, defaultOn));
           cipherList.addElement(
             new AbstractCipher(resource.getString("SSL3CIPHERPREF_TRIPLEDES168SHA"),
               RSA_3DES_SHA, defaultOn));
           cipherList.addElement(
             new AbstractCipher(resource.getString("SSL3CIPHERPREF_TRIPLEDES168SHA"),
               RSA_FIPS_3DES_SHA, defaultOn));
           if (hasFortezza) {
               cipherList.addElement(
                 new AbstractCipher(resource.getString("SSL3CIPHERPREF_FORT80SHA"),
                   FORTEZZA, !defaultOn));
               cipherList.addElement(
                 new AbstractCipher(resource.getString("SSL3CIPHERPREF_RC4128FORTSHA"),
                   FORTEZZA_RC4_128_SHA, !defaultOn));
               cipherList.addElement(
                 new AbstractCipher(resource.getString("SSL3CIPHERPREF_NOENCRYPTIONFORSHA"),
                   FORTEZZA_NULL, !defaultOn));
           }
       }
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL3CIPHERPREF_NOENCRYPTION"),
           RSA_NULL_MD5, !defaultOn));
       title = resource.getString("SSL3CIPHERPREF_TITLE");
    }

    public String getTitle() {
        return title;
    }

    public Vector getCipherList() {
        return cipherList;
    }
}

