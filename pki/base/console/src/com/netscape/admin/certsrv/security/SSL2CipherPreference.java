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

/**
 *
 * Convenient class to construct SSL2 cipher preference toggle pane
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 *
 * @see com.netscape.admin.certsrv.security.SSL2CipherSet
 * @see com.netscape.admin.certsrv.security.ToggleCipherPreferencePane
 * @see com.netscape.admin.certsrv.security.SSL3CipherPreference
 */
public class SSL2CipherPreference extends ToggleCipherPreferencePane implements ICipherConstants {

    //private static final String  sslVersion = "SSL 2.0 Ciphers";

    /**
     * Create a SSL2 cipher preference toggle pane
     *
     * @param isDomestic show domestic ssl2 ciphers if true
     *
     */
    public SSL2CipherPreference(boolean isDomestic) {
        super(new SSL2CipherSet(isDomestic), true);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.getContentPane().add(new SSL2CipherPreference(true));
     f.getContentPane().add(new AbstractCipherPreference(new SSL2CipherSet(true)));
     f.pack();
     f.show();
     }*/

}
