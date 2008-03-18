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

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.security.*;
import java.util.*;

/**
 * Constructs a SSL2 cipher suites.
 * 
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class CMSSSL2CipherSet implements ICipherConstants, IAbstractCipherSet {
    Vector cipherList = new Vector();
    String title;

    boolean defaultOn = true;

    /**
     * Create a SSL2 cipher set
     * @param isDomestic show all ssl2 ciphers for domestic and export version.
     */
    public CMSSSL2CipherSet(boolean isDomestic) {
       ResourceBundle resource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL2CIPHERPREF_RC440MD5"),
           RC4EXPORT, defaultOn));
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL2CIPHERPREF_RC240MD5"),
           RC2EXPORT, defaultOn));
       cipherList.addElement(
         new AbstractCipher(resource.getString("SSL2CIPHERPREF_DES56MD5"),
           DES, defaultOn));
       if (isDomestic) {
           cipherList.addElement(
             new AbstractCipher(resource.getString("SSL2CIPHERPREF_RC4128MD5"),
               RC4, defaultOn));
           cipherList.addElement(
             new AbstractCipher(resource.getString("SSL2CIPHERPREF_RC2128MD5"),
               RC2, defaultOn));
           cipherList.addElement(
             new AbstractCipher(resource.getString("SSL2CIPHERPREF_TRIPLEDES168MD5"),
               DES3, defaultOn));
       }
       title = resource.getString("SSL2CIPHERPREF_TITLE");
    }

    public String getTitle() {
        return title;
    }

    public Vector getCipherList() {
        return cipherList;
    }
}

