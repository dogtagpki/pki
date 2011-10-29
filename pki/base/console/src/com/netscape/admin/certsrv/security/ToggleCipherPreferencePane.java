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

import com.netscape.management.nmclf.*;

/**
 *
 * Convenient class to create a toggle cipher preference pane
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 * @see com.netscape.admin.certsrv.security.SSL2CipherPreference
 * @see com.netscape.admin.certsrv.security.SSL3CipherPreference
 */
public class ToggleCipherPreferencePane extends AbstractCipherPreference implements ICipherConstants {
    private JCheckBox on;
    private JPanel top = new JPanel();
    boolean _ismodified;

    boolean oldValue;

    /**
     * Create a toggle cipher preference pane
     *
     * @param cipherSet  Interface to obtain cipher preference list, and title for toggle pane
     *
     */
    public ToggleCipherPreferencePane(IAbstractCipherSet cipherSet) {
        this(cipherSet, true);
    }

    /**
      * Create a toggle cipher preference pane
      *
      *
      * @param cipherSet  Interface to obtain cipher preference list, and title for toggle pane
      * @param enabled    enable/disable toggle pane
      *
      */
    public ToggleCipherPreferencePane(IAbstractCipherSet cipherSet,
            boolean enabled) {
        oldValue = enabled;

        on = new JCheckBox(cipherSet.getTitle(), enabled);
        on.setActionCommand("ENABLED");
        on.addActionListener(new actionListener());

        top.setAlignmentX(0.0f);
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(on);
        setBorder( new CompoundBorder(
                new ToggleBorder(top, SwingConstants.TOP),
                new EmptyBorder(0, SuiConstants.COMPONENT_SPACE,
                SuiConstants.COMPONENT_SPACE, 0)));
        add(top);

        initialize(cipherSet);

        add(Box.createHorizontalGlue());
    }

    class actionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("ENABLED")) {
                _ismodified = true;
                setEnableAll(on.isSelected());
            }
        }
    }


    /**
      * Enable or disable toggle pane
      *
      * @param enable
      *
      */
    public void setEnabled(boolean enable) {
        on.setSelected(enable);
        super.setEnableAll(enable);
    }

    /**
      * Check weather toggle pane is enabled
      *
      */
    public boolean isEnabled() {
        return on.isSelected();
    }


    //steal from Mac's layout manager
    class ToggleBorder extends EtchedBorder {
        private JComponent _switchPanel;
        private int _switchAlign;

        public ToggleBorder(JComponent sp, int align) {
            _switchPanel = sp;
            _switchAlign = align;
        }

        public void paintBorder(Component c, Graphics g, int x, int y,
                int width, int height) {
            Color save = g.getColor();

            int top = y + (_switchPanel.getHeight() >> 1);
            int new_height = height - top;

            BorderUIResource.getEtchedBorderUIResource().paintBorder(c,
                    g, x, top, width, new_height);
        }
    }

    /**
      * Check weather any ciphers has been modified
      *
      * @see #isModified
      * @see #setSaved
      *
      */
    public boolean isModified() {
        return (_ismodified | super.isModified());
    }

    /**
      * Reset all changes since last save
      *
      * @see #setSaved
      */
    public void reset() {
        setEnabled(oldValue);
        _ismodified = false;
        super.reset();
    }


    /**
      * Set the state to save.
      *
      * @see #reset
      */
    public void setSaved() {
        oldValue = isEnabled();
        _ismodified = false;
        super.setSaved();
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.getContentPane().add(new ToggleCipherPreferencePane(new SSL3CipherSet(true, true)));
     f.pack();
     f.show();
     }*/

}



