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
package com.netscape.management.client.security;

/**
 *
 * Encryption options - individule server should implement this interface
 * then pass this interface to the Encryption panel.
 * 
 * This interfaces is used for encryption panel to query server specific
 * encryption settings.
 *
 */
public interface IEncryptionOptions {
    /**
     * Invoked when security is enabled/disabled
     *
     * @param enabled true if enabled (checkbox is checked), false otherwise
     */
    public abstract void securityEnabledChanged(boolean enabled);

    /**
     * Invoked when a cipher family is enabled/disabled
     *
     * @param cipherFamily name (ie. RSA, Fortezza, etc) of the cipher family that got enabled/disabled
     * @param enabled true if enabled (checkbox is checked), false otherwise
     */
    public abstract void cipherFamilyEnabledChanged(String cipherFamily, boolean enabled);

    /**
     * Invoked when a security device selection got changed
     *
     * @param cipherFamily name (ie. RSA, Fortezza, etc) of the cipher family that uses this device
     * @param device name (ie. internal (software), slot 1, etc) of the security device
     */
    public abstract void selectedDeviceChanged(String cipherFamily, String device);

    /**
     * Invoked when a certificate selection got changed
     *
     * @param cipherFamily name (ie. RSA, Fortezza, etc) of the cipher family that uses this certificate
     * @param certName name (ie. server-cert, netscape, etc) of the certificate
     */
    public abstract void selectedCertificateChanged(String cipherFamily, String certName);

    /**
     * Invoked when user click on "Setting..." button.  the expected behavior here is
     * cipher preference dialog (defined by individual team) will pop up.
     *
     * @param cipherFamily name (ie. RSA, Fortezza, etc) of the cipher family that uses this device
     * @see com.netscape.management.client.security.CipherPreferenceDialog
     */
    public abstract void showCipherPreferenceDialog(String cipherFamily);

    /**
     * @return true is security is enabled, false otherwise
     */
    public abstract boolean isSecurityEnabled();

    /**
     * @return true if cipher family should be enabled
     *
     */
    public abstract boolean isCipherFamilyEnabled(String cipherFamily);



    /**
     * Get name of the selected security device to used
     *
     * @param cipherFamily name (ie. RSA, Fortezza, etc) of the cipher family that uses this device
     * @return name (ie. internal (software), slot 1, etc) of the security device.   If null is return, default (first entry on the list) will be used
     */
    public abstract String getSelectedDevice(String cipherFamily);

    /**
     * Get name of the certificate to use
     *
     * @param cipherFamily name (ie. RSA, Fortezza, etc) of the cipher family that uses this certificate
     * @return name (ie. server-cert, netscape, etc) of the certificate If null is return, default (first entry on the list) will be used
     */
    public abstract String getSelectedCertificate(String cipherFamily);



    /**
     * Set supported cipher to export or domestic
     * This bit is to let the server encryption panel know wheather or not
     * the server support domestic cipher or not.
     *
     * @param domestic true if server is domestic build false if it is export build
     *
     */
    public abstract void setSecurityIsDomestic(boolean domestic);
}
