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

/**
 * Interface which specify the encryption panel listen method.
 *
 * @author  <a href=mailto:dshihcm@netscape.com>Chih Ming Shih</a>
 * @version 0.2 9/3/97
 */

public interface IEncryptionPaneListener {

    /**
     * called when cipher change state(on/off, token name change, cert name change)
     *
     * @param cipherEnbled  enable cipher
     * @param cipherName    cipher name
     * @param tokenName     token name
     * @param certName      certificate name
     */
    public void cipherStateChanged(boolean cipherEnabled,
            String cipherName, String tokenName, String certName);

    /**
     * called when ssl change state
     *
     * @param sslEnabled  enable ssl
     */
    public void sslStateChanged(boolean sslEnabled);

    /**
     * called to invoke cipher preference dialog
     *
     */
    public void showCipherPreferenceDialog();
}
