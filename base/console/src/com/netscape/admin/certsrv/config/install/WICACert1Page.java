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
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * Setup CA signing cert for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICACert1Page extends WizardBasePanel implements IWizardPanel {
    private JComboBox mKeyTypeBox;
    private JComboBox mKeyLengthBox;
    //private JComboBox mTokenBox;
    //private JPasswordField mPasswordText;

    private static final String PANELNAME = "CACERT1WIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WICACert1Page() {
        super(PANELNAME);
        init();
    }

    public boolean initializePanel(WizardInfo info) {
        return true;
    }

    public boolean isLastPage() {
        return false;
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

        JTextArea desc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERT1WIZARD_TEXT_HEADING_LABEL"), 80), 2, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

/*
        JTextArea desc1 = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERT1WIZARD_TEXT_TOKENHEADING_LABEL"), 80), 1, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc1, gbc);

        JLabel tokenLbl = makeJLabel("TOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(tokenLbl, gbc);

        mTokenBox = new JComboBox();
        mTokenBox.addItem("internal");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mTokenBox, gbc);

        JTextArea dummy = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,0,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy, gbc);

        JTextArea desc2 = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERT1WIZARD_TEXT_HARDWARE_LABEL"), 80), 1, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(2*COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc2, gbc);

        JLabel pwdLbl = makeJLabel("PWD");
        mPasswordText = makeJPasswordField(20);
        //JTextArea dummy1 = createTextArea(" ", 1, 10);
        //CMSAdminUtil.addComponents(this, pwdLbl, mPasswordText, dummy1, gbc);
        CMSAdminUtil.addComponents(this, pwdLbl, mPasswordText, gbc);
*/

        JTextArea desc3 = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERT1WIZARD_TEXT_KEY_LABEL"), 80), 1, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(2*COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc3, gbc);

        JPanel panel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);

        JLabel keyTypeLbl = makeJLabel("KEYTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel.add(keyTypeLbl, gbc);

        mKeyTypeBox = makeJComboBox("KEYTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        panel.add(mKeyTypeBox, gbc);

        JLabel keyLengthLbl = makeJLabel("KEYLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE,0,COMPONENT_SPACE);
        gbc.gridheight = gbc.REMAINDER;
        panel.add(keyLengthLbl, gbc);

        mKeyLengthBox = makeJComboBox("KEYLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        //gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,0,COMPONENT_SPACE);
        panel.add(mKeyLengthBox, gbc);

        JLabel unitLbl = makeJLabel("UNITS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(0, 0,0,COMPONENT_SPACE);
        panel.add(unitLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
