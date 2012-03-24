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
package com.netscape.admin.certsrv.config.install;

import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * This page is to install the certificate in the internal token. The user can 
 * import the cert from the file or paste the Base 64 encoded blob in the 
 * text area.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIInstallCert1Page extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mFileBtn;
    private JRadioButton mBase64Btn;
    private JTextField mFileText;
    private JTextArea mBase64Text;
    private JButton mPaste;
    private static final String PANELNAME = "INSTALLCERT1WIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";
    
    WIInstallCert1Page() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        return true; 
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        mFileBtn = makeJRadioButton("FILE", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mFileBtn, gbc);

        mFileText = makeJTextField(50);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE, 0);
        add(mFileText, gbc);

        mBase64Btn = makeJRadioButton("BASE64", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mBase64Btn, gbc);

        JTextArea desc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
          "INSTALLCERT1WIZARD_TEXT_DESC_LABEL"), 80), 2, 80);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mPaste = makeJButton("PASTE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mPaste, gbc);

        mBase64Text = new JTextArea(null, null, 0, 0);
        mBase64Text.setLineWrap(true);
        mBase64Text.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(mBase64Text, 
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(50, 20));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, 
          COMPONENT_SPACE);
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = gbc.REMAINDER;
        add(scrollPane, gbc);

        JLabel dummy = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.anchor = gbc.NORTHWEST;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        add(dummy, gbc);

        ButtonGroup buttonGrp = new ButtonGroup();
        buttonGrp.add(mFileBtn);
        buttonGrp.add(mBase64Btn);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
