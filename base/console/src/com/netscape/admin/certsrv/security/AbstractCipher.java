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

import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.nmclf.*;

/**
 *
 * Representation of a cipher under cipher preference.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 * @see        com.netscape.admin.certsrv.security.AbstractCipher
 * @see        com.netscape.admin.certsrv.security.IAbstractCipherSet
 * @see        com.netscape.admin.certsrv.security.AbstractCipher
 */

public final class AbstractCipher extends JCheckBox {

    /**
     *
     *  Symbolic name, used for storage purpose
     *  for example we currently use ssl2-RC4EXPORT to represent:
     *     "RC4 with 40 bit encryption and MD5 message authentication"
     */
    private String symbolicName = "";

    /**
     * Create an abstric cipher
     *
     * @param displayName  cipher representation to be displayed
     * @param symbolicName cipher name used for reference and storage
     *
     */
    public AbstractCipher(String displayName, String symbolicName) {
        this(displayName, symbolicName, false);
    }

    /**
      * Create an abstric cipher
      *
      * @param displayName  cipher representation to be displayed
      * @param symbolicName cipher name used for reference and storage
      * @param enabled      enable cipher
      *
      */
    public AbstractCipher(String displayName, String symbolicName,
            boolean enabled) {
        super(displayName, enabled);
        this.symbolicName = symbolicName;
    }

    /**
      *
      * Get symbolic name
      *
      * @return string, symbolic name
      *
      */
    public String getSymbolicName() {
        return symbolicName;
    }

}
