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

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.plaf.BorderUIResource;

import com.netscape.admin.certsrv.security.AbstractCipherPreference;
import com.netscape.admin.certsrv.security.IAbstractCipherSet;
import com.netscape.admin.certsrv.security.ICipherConstants;
import com.netscape.management.nmclf.SuiConstants;

/**
 * Constructs a Cipher preference pane.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CMSCipherPreferencePane extends AbstractCipherPreference implements ICipherConstants {
    private JCheckBox on;
    private JPanel top = new JPanel();
    boolean _ismodified;
    boolean oldValue;

    public CMSCipherPreferencePane(IAbstractCipherSet cipherSet) {
        this(cipherSet, true);
    }

    public CMSCipherPreferencePane(IAbstractCipherSet cipherSet, boolean enabled) {
        oldValue = enabled;
        on = new JCheckBox(cipherSet.getTitle(), enabled);
        on.setActionCommand("ENABLED");
        on.addActionListener(new actionListener());
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.add(on);
        setBorder(new CompoundBorder(new ToggleBorder(top, SwingConstants.TOP),
          new EmptyBorder(0, SuiConstants.COMPONENT_SPACE, SuiConstants.COMPONENT_SPACE, 0)));
        add(top);
        initialize(cipherSet);
        add(Box.createHorizontalGlue());
    }

    class actionListener implements ActionListener{
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("ENABLED")) {
                _ismodified = true;
                setEnableAll(on.isSelected());
            }
        }
    }

    public void setEnabled(boolean enable) {
        on.setSelected(enable);
        super.setEnableAll(enable);
    }

    public boolean isEnabled() {
        return on.isSelected();
    }


    class ToggleBorder extends EtchedBorder {
        private JComponent _switchPanel;

        public ToggleBorder(JComponent sp, int align) {
            _switchPanel = sp;
        }

        public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
            Color save = g.getColor();
            int top = y + (_switchPanel.getHeight() >> 1);
            int new_height = height - top;
            BorderUIResource.getEtchedBorderUIResource().paintBorder(c, g, x, top, width, new_height);
        }
    }

    public boolean isModified() {
        return (_ismodified | super.isModified());
    }

    public void reset() {
        setEnabled(oldValue);
        _ismodified = false;
        super.reset();
    }

    public void setSaved() {
        oldValue = isEnabled();
        _ismodified = false;
        super.setSaved();
    }
}

