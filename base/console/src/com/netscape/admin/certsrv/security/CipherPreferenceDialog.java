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

import java.awt.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 * General dialog which display the ciper preference.
 *
 * @author  <a href=mailto:shihcm@netscape.com>Chih Ming Shih</a>
 * @version 0.2 9/3/97
 */

public class CipherPreferenceDialog extends AbstractDialog implements ICipherConstants {
    SSL2CipherPreference ssl2CipherPref = null;
    SSL3CipherPreference ssl3CipherPref = null;

    /**SSL Version 2*/
    public final static int SSL2 = 1;
    /**SSL Version 3*/
    public final static int SSL3 = 2;

    private JPanel cipherPreferencePane;

    boolean modified = true;
    Help help;


    /**
     * Constructor, ciphers will default to SSL2 and SSL3
     *
     * @param parent      The owner of the dialog
     * @param isDomestic  Software built domestic(allow stonger cipher) or export use
     *
     */
    public CipherPreferenceDialog(JFrame parent, boolean isDomestic) {
        this(parent, isDomestic, false);
    }

    /**
      * Constructor, ciphers will default to SSL2 and SSL3
      *
      * @param parent      The owner of the dialog
      * @param isDomestic  Software built domestic(allow stonger cipher) or export use
      * @param hasFortezza Fortezza enabled server
      *
      */
    public CipherPreferenceDialog(JFrame parent, boolean isDomestic,
            boolean hasFortezza) {
        this(parent, isDomestic, hasFortezza, SSL2 | SSL3);
    }


    /**
      * Constructor
      *
      * @param parent      The owner of the dialog
      * @param isDomestic  Software built domestic(allow stonger cipher) or export use
      * @param hasFortezza Fortezza enabled server
      * @param SSLVersion  SSL version ciphers to display, SSL2 and/or SSL3
      *
      */
    public CipherPreferenceDialog(JFrame parent, boolean isDomestic,
            boolean hasFortezza, int SSLVersion) {
        super(parent, "", true, OK | CANCEL | HELP);

        ResourceSet r = new CipherResourceSet();
        help = new Help(r);


        cipherPreferencePane = new JPanel();
        cipherPreferencePane.setLayout(
                new BoxLayout(cipherPreferencePane, BoxLayout.Y_AXIS));
        if ((SSL2 & SSLVersion) == SSL2) {
            ssl2CipherPref = new SSL2CipherPreference(isDomestic);
            cipherPreferencePane.add(ssl2CipherPref);
        }

        if ((SSL3 & SSLVersion) == SSL3) {
            ssl3CipherPref =
                    new SSL3CipherPreference(isDomestic, hasFortezza);
            cipherPreferencePane.add(ssl3CipherPref);
        }

        cipherPreferencePane.add(Box.createRigidArea(new Dimension(0, 4)));

        getContentPane().add(cipherPreferencePane);

        pack();
    }

    /**
      * Remove SSL preference pane, currently only support SSL2 and SSL3.
      * Will support Fortezza if only Phaos will support it.
      *
      * @param sslVersion SSL version to be removed
      *
      */
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

    /**
      * Determines whether a cipher is enabled.
      * @param cipher Cipher name
      *
      * @see #getSSLPreference
      * @see #setCipherEnabled
      *
      * @return True if a cipher is enabled
      */
    public boolean isCipherEnabled(String cipher) {
        return ( ((ssl2CipherPref == null) ? false :
                ssl2CipherPref.isCipherEnabled(cipher)) ||
                ((ssl3CipherPref == null) ? false :
                ssl3CipherPref.isCipherEnabled(cipher)));
    }

    /**
      * Enable or disable a cipher.
      * @param cipher Cipher name
      * @param enable Enable the cipher
      *
      * @see #isCipherEnabled
      * @see #getSSLPreference
      */
    public void setCipherEnabled(String cipher, boolean enable) {
        if (ssl2CipherPref != null) {
            ssl2CipherPref.setCipherEnabled(cipher, enable);
        }
        if (ssl3CipherPref != null) {
            ssl3CipherPref.setCipherEnabled(cipher, enable);
        }
    }

    /**
      * Get a list of supported ciphers.
      * @param sslVersion SSL version
      *
      * @see #isCipherEnabled
      * @see #setCipherEnabled
      *
      * @return An array that contains the name of supported ciphers under SSL version
      */
    public String[] getSSLPreference(int sslVersion) {
        String[] ciphers = null;

        switch (sslVersion) {
        case SSL2:
            ciphers = ssl2CipherPref.getCipherList();
            break;
        case SSL3:
            ciphers = ssl3CipherPref.getCipherList();
            break;
        default :
            //programmer's fault, do nothing here
            Debug.println("Cipher Preference : Invalid ssl version "+
                    sslVersion);
            break;
        }
        return ciphers;
    }


    /**
      * Determines whether a cipher group(ssl version) is enabled.
      * @param sslVersion SSL version
      *
      * @see #setSSLEnabled
      *
      * @return True if the speicified SSL version is enabled
      */
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
            //programmer's fault, do nothing here
            Debug.println("Cipher Preference : Invalid ssl version "+
                    sslVersion);
            break;
        }
        return enable;
    }

    /**
      * Enable or disable a cipher group.
      * @param sslVersion SSL Version
      * @param enable     Enable the SSL version
      *
      * @see #isSSLEnabled
      */
    public void setSSLEnabled(int sslVersion, boolean enable) {
        switch (sslVersion) {
        case SSL2:
            ssl2CipherPref.setEnabled(enable);
            break;
        case SSL3:
            ssl3CipherPref.setEnabled(enable);
            break;
        default:
            //programmer's fault, do nothing here
            Debug.println("Cipher Preference : Invalid ssl version "+
                    sslVersion);
            break;
        }
    }



    /**
      * Check weather any ciphers has been modified
      *
      */
    public boolean isModified() {
        return modified;
    }

    /**
      * Reset all changes since last save
      *
      * @see #setSaved
      */
    public void reset() {
        if (ssl2CipherPref != null) {
            ssl2CipherPref.reset();
        }
        if (ssl3CipherPref != null) {
            ssl3CipherPref.reset();
        }
    }



    /**
      * Set the state to save.
      *
      * @see #reset
      */
    public void setSaved() {
        if (ssl2CipherPref != null) {
            ssl2CipherPref.setSaved();
        }

        if (ssl3CipherPref != null) {
            ssl3CipherPref.setSaved();
        }
    }

    /**
      * Set the state to save.
      *
      * @see #reset
      * @derprecated replaced by setSaved()
      */
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
        modified = (((ssl2CipherPref == null) ? false :
                ssl2CipherPref.isModified()) ||
                ((ssl3CipherPref == null) ? false :
                ssl3CipherPref.isModified()));
        setSaved();
        super.okInvoked();
    }


    protected void helpInvoked() {
        help.help("SSL", "Preference");
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();

     try {
     	UIManager.setLookAndFeel("javax.swing.plaf.windows.WindowsLookAndFeel");
     	SwingUtilities.updateComponentTreeUI(f.getContentPane());
     } catch (Exception e) {}

     CipherPreferenceDialog c = new CipherPreferenceDialog(f, true, false, SSL3);

     c.show();
     }*/
}
