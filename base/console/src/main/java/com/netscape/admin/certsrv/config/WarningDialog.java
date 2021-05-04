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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ResourceBundle;

import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;

/**
 * Certificate Information dialog
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.managecert
 */
public class WarningDialog extends JDialog
    implements ActionListener {
    private String PREFIX = "WARNINGDIALOG";

    private ResourceBundle mResource;
    private JButton mClose;
    private String mKey;

    public WarningDialog(JFrame parent, String key) {
        super(parent,true);
        mKey = key;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(500, 300);
        setResizable(false);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mClose)) {
            this.hide();
            this.dispose();
        }
    }

    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill=GridBagConstraints.BOTH;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(content, gbc);
        center.add(content);

        //action panel
        JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(action, gbc);
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        center.add(action);

        getContentPane().add("Center",center);

        this.show();
    }

    private JPanel makeActionPane() {
        mClose = CMSAdminUtil.makeJButton(mResource, PREFIX, "CLOSE",
          null, this);

        Dimension d = mClose.getMinimumSize();
        if (d.width < CMSAdminUtil.DEFAULT_BUTTON_SIZE) {
            d.width = CMSAdminUtil.DEFAULT_BUTTON_SIZE;
            mClose.setMinimumSize(d);
        }
        JButton[] buttons = {mClose};
        return CMSAdminUtil.makeJButtonPanel( buttons );
    }

    private JPanel makeContentPane() {
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout(gb3);
/*
        content.setBorder(CMSAdminUtil.makeTitledBorder(mResource,
          "CERTINFODIALOG", "CERT"));
*/

        CMSAdminUtil.resetGBC(gbc);
        Icon icon = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON);
        JLabel label = new JLabel(icon);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE,CMSAdminUtil.COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        content.add(label, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(PREFIX+mKey),65),10,65);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
        JScrollPane scrollPane = new JScrollPane(desc,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill= GridBagConstraints.BOTH;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        content.add(scrollPane, gbc);

        return content;
    }
}

