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
import javax.swing.plaf.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 *
 * Abstract cipher preference panel.
 * Use with AbstractCipher and IAbstractCipherSet to customize server
 * specific cipher preference dialog/panel.
 *
 * @version    1.0    98/07/10
 * @author     shihcm@netscape.com
 *
 * @see        com.netscape.admin.certsrv.security.AbstractCipher
 * @see        com.netscape.admin.certsrv.security.IAbstractCipherSet
 * @see        com.netscape.admin.certsrv.security.AbstractCipher
 */
public class AbstractCipherPreference extends JPanel {

    /**
     * Main listener for all the cipher component under AbstractCipherPreference panel.
     * This listener will catch all the cipher event(on/off) occures with in this panel.
     */
    CipherPrefActionListener listener = new CipherPrefActionListener();

    /**
     * Other listeners are stored in this vector, event catch in the "listener"(above) will
     * also be routed to all the listener store in this vector
     * Listener stored here are added by programmer via addActionListener(actionListener) call
     */
    Vector listenerList = new Vector();


    /**
     * This panel holds all the Ciper entry
     */
    JPanel cipherPane = new JPanel();

    /**
     * To determain whether if any cipher[s] changed status since last save.
     */
    boolean _ismodified = false;

    /**
     * Store the old setting, for reset purpose.
     */
    Hashtable oldValue = new Hashtable();

    /**
     * Create an abstract cipher preference
     *
     *
     */
    public AbstractCipherPreference() {}

    /**
      * Create an abstract cipher preference
      *
      * @param cipherList Interface to getCipherList()
      *
      *
      */
    public AbstractCipherPreference(IAbstractCipherSet cipherList) {
        super();
        initialize(cipherList);
    }


    class CipherPrefActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            _ismodified = true;
            Enumeration l = listenerList.elements();
            while (l.hasMoreElements()) {
                ((ActionListener)(l.nextElement())).actionPerformed(e);
            }
        }
    }


    /**
      * Initializer for cipher preference.
      * Cipher are obtain via getCipherList() from IAbstractCipherSet
      *
      * @param cipherList Interface to getCipherList()
      *
      *
      */
    protected void initialize(IAbstractCipherSet cipherList) {

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        cipherPane.setLayout(new BoxLayout(cipherPane, BoxLayout.Y_AXIS));
        add(cipherPane);

        Vector ciphers = cipherList.getCipherList();
        for (Enumeration e = ciphers.elements(); e.hasMoreElements();) {
            addCipher((AbstractCipher)(e.nextElement()));
        }
    }

    /**
      *
      * Adds an ActionListener to all the ciphers
      *
      * @param l
      *
      */
    public void addActionListener(ActionListener l) {
        if (!(listenerList.contains(l))) {
            listenerList.addElement(l);
        }
    }


    /**
      *
      * Adds cipher ui
      *
      * @param l
      *
      */
    public void addCipher(AbstractCipher cipher) {
        oldValue.put(cipher.getSymbolicName(),
                cipher.isSelected() ? "1":"0");
        cipherPane.add(cipher);
        cipher.addActionListener(listener);
    }


    /**
      *
      * Call setEnable(enabled) on each cipher.
      * This is different then set cipher selected state.
      * if cipher selected state on all cipher is required try
      * getCipherList() then setCipherEnabled(boolean) on each
      * cipher.
      *
      * @param enabled  enable/disable all ciphers
      *
      */
    public void setEnableAll(boolean enabled) {
        Component[] c = cipherPane.getComponents();
        for (int i = c.length - 1; i >= 0; i--) {
            c[i].setEnabled(enabled);
        }
    }



    /**
      *
      * Get entire cipher list
      *
      *
      */
    public String[] getCipherList() {
        Component[] c = cipherPane.getComponents();
        String[] ciphers = new String[c.length];
        for (int i = c.length - 1; i >= 0; i--) {
            ciphers[i] = ((AbstractCipher) c[i]).getSymbolicName();
        }
        return ciphers;
    }

    private AbstractCipher findCipher(String symbolicName) {
        Component[] c = cipherPane.getComponents();

        AbstractCipher cipher = null;

        for (int i = c.length - 1; i >= 0; i--) {
            if (((AbstractCipher) c[i]).getSymbolicName().
                    equalsIgnoreCase(symbolicName)) {
                cipher = (AbstractCipher) c[i];
            }
        }

        return cipher;
    }


    /**
      *
      * Set cipher to selected state
      *
      * @param cipher   Cipher to enable/disable
      * @param enabled  enable cipher if true
      *
      */
    public void setCipherEnabled(String cipher, boolean enabled) {
        AbstractCipher c = findCipher(cipher);
        if (c != null) {
            c.setSelected(enabled);
        }
    }

    /**
      *
      * Check weather a cipher is enabled or disabled
      *
      * @param cipher   Cipher to check
      *
      */
    public boolean isCipherEnabled(String cipher) {
        AbstractCipher c = findCipher(cipher);
        if (c != null) {
            return c.isSelected();
        }
        return false;
    }

    /**
      * Check weather any ciphers has been modified
      *
      * @see #isModified
      * @see #setSaved
      *
      */
    public boolean isModified() {
        return _ismodified;
    }

    /**
      * Reset all changes since last save
      *
      * @see #setSaved
      */
    public void reset() {
        Enumeration keys = oldValue.keys();
        while (keys.hasMoreElements()) {
            String cipherName = (String)(keys.nextElement());
            setCipherEnabled(cipherName,
                    "1".equals(oldValue.get(cipherName)) ? true : false);
        }
        _ismodified = false;
    }


    /**
      * Set the state to saved.
      *
      * @see #reset
      */
    public void setSaved() {
        oldValue.clear();

        Component[] c = cipherPane.getComponents();
        for (int i = c.length - 1; i >= 0; i--) {
            AbstractCipher cipher = (AbstractCipher)(c[i]);
            oldValue.put(cipher.getSymbolicName(),
                    cipher.isSelected() ? "1":"0");
        }

        _ismodified = false;
    }
}
