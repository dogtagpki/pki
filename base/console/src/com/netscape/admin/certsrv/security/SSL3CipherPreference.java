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
 * Convenient class to construct SSL3 cipher preference toggle pane
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 *
 * @see com.netscape.admin.certsrv.security.SSL3CipherSet
 * @see com.netscape.admin.certsrv.security.ToggleCipherPreferencePane
 * @see com.netscape.admin.certsrv.security.SSL2CipherPreference
 */
public class SSL3CipherPreference extends ToggleCipherPreferencePane implements ICipherConstants {


    /**
     * Create a SSL3 cipher preference toggle pane
     *
     * @param isDomestic  show domestic ssl3 ciphers if true
     * @param hasFortezza show fortezza ciphers if true
     *
     */
    public SSL3CipherPreference(boolean isDomestic, boolean hasFortezza) {
        super(new SSL3CipherSet(isDomestic, hasFortezza), true);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     SSL3CipherPreference s = new SSL3CipherPreference(false, false);
     f.getContentPane().add(s);
     f.pack();
     f.show();
     String[] my = s.getCipherList();
     for (int i=0; i <my.length; i++) {
     System.out.println(my[i]);
     }

     System.out.println(s.isCipherEnabled(SSL3CipherPreference.FORTEZZA));
     s.setCipherEnabled(SSL3CipherPreference.FORTEZZA, false);
     System.out.println(s.isCipherEnabled(SSL3CipherPreference.FORTEZZA));
     }*/

}
