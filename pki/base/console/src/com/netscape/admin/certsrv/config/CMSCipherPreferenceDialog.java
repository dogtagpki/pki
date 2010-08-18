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

import com.netscape.admin.certsrv.security.CipherPreferenceDialog;
import com.netscape.management.client.util.*;
import javax.swing.*;
import java.awt.*;

/**
 * Allows user to select the SSL cipher preferences.
 * 
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CMSCipherPreferenceDialog extends AbstractDialog {

    CMSSSL2CipherPreference ssl2CipherPref = null;
    CMSSSL3CipherPreference ssl3CipherPref = null;

    public final static int SSL2 = 1;
    public final static int SSL3 = 2;
    private JPanel cipherPreferencePane;
    boolean modified = true;
    private static final ResourceSet mHelpResource =
      new ResourceSet("com.netscape.admin.certsrv.certsrv-help");
    Help help;
    
    public CMSCipherPreferenceDialog(JFrame parent, boolean isDomestic) {
        this(parent, isDomestic, false);
    }

    public CMSCipherPreferenceDialog(JFrame parent, boolean isDomestic, 
      boolean hasFortezza) {
        this(parent, isDomestic, hasFortezza, SSL2|SSL3);
    }

    public CMSCipherPreferenceDialog(JFrame parent, boolean isDomestic, 
      boolean hasFortezza, int SSLVersion) {

        super(parent, "", true, OK | CANCEL | HELP);
        cipherPreferencePane = new JPanel();
        cipherPreferencePane.setLayout(new BoxLayout(cipherPreferencePane, BoxLayout.Y_AXIS));
        if ((SSL2 & SSLVersion) == SSL2) {
            ssl2CipherPref = new CMSSSL2CipherPreference(isDomestic);
            cipherPreferencePane.add(ssl2CipherPref);
        }

        if ((SSL3 & SSLVersion) == SSL3) {
            ssl3CipherPref = new CMSSSL3CipherPreference(isDomestic, hasFortezza);
            cipherPreferencePane.add(ssl3CipherPref);
        }

        cipherPreferencePane.add(Box.createRigidArea(new Dimension(0,4)));
        getContentPane().add(cipherPreferencePane);
        pack();
    }

    public void removeSSLVersion(int sslVersion) {
        switch (sslVersion) {
            case SSL2:
               cipherPreferencePane.remove(ssl2CipherPref);
               break;
            case SSL3:
              cipherPreferencePane.remove(ssl3CipherPref);
              break;
        }
        pack();
    }

    public boolean isCipherEnabled(String cipher) {
        return (((ssl2CipherPref == null)?false:ssl2CipherPref.isCipherEnabled(cipher))||
          ((ssl3CipherPref == null)?false:ssl3CipherPref.isCipherEnabled(cipher)));
    }

    public void setCipherEnabled(String cipher, boolean enable) {
        if (ssl2CipherPref != null) {
            ssl2CipherPref.setCipherEnabled(cipher, enable);
        }
        if (ssl3CipherPref != null) {
            ssl3CipherPref.setCipherEnabled(cipher, enable);
        }
    }

    public String[] getSSLPreference(int sslVersion) {
        String[] cipher = null;
        switch(sslVersion) {
            case SSL2:
                cipher = ssl2CipherPref.getCipherList();
            break; 
            case SSL3:
                cipher = ssl3CipherPref.getCipherList();
            break; 
            default:
            break;
        }

        return cipher;
    }

    public boolean isSSLEnabled(int sslVersion) {
        boolean enable = false;
        switch (sslVersion) {
            case SSL2:
                enable = ssl2CipherPref.isEnabled();
            break;

            case SSL3:
                enable = ssl3CipherPref.isEnabled();
            break;

            default:
            break;
        }

        return enable;
    }

    public void setSSLEnabled(int sslVersion, boolean enable) {
        switch (sslVersion) {
            case SSL2:
                ssl2CipherPref.setEnabled(enable);
            break;

            case SSL3:
                ssl3CipherPref.setEnabled(enable);
            break;

            default:
            break;
        }
    }

    public boolean isModified() {
        return modified;
    }

    public void reset() {
        if (ssl2CipherPref != null)
            ssl2CipherPref.reset();

        if (ssl3CipherPref != null)
            ssl3CipherPref.reset();
    }

    public void setSaved() {
        if (ssl2CipherPref != null) {
            ssl2CipherPref.setSaved();
        }

        if (ssl3CipherPref != null) {
            ssl3CipherPref.setSaved();
        }
    }

    public void setSaved(boolean saved) {
        if (saved) {
            if (ssl2CipherPref != null) {
                ssl2CipherPref.setSaved();
            }
            if (ssl3CipherPref != null) {
                ssl3CipherPref.setSaved();
            }
        }
    }

    protected void cancelInvoked() {
        reset();
        modified = false;
        super.cancelInvoked();
    }

    protected void okInvoked() {
        modified = (((ssl2CipherPref==null)?false:ssl2CipherPref.isModified()) ||
          ((ssl3CipherPref==null)?false:ssl3CipherPref.isModified()));
        setSaved();
        super.okInvoked();
    }

    protected void helpInvoked() {
      new Help(mHelpResource).help("configuration-overview");
//    help.help("SSL", "Preference");
    }
}

