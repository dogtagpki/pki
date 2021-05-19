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
import com.netscape.admin.certsrv.wizard.*;

/**
 * This page allows the user to generate a CA certificate request.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICACertPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mSelfBtn, mSubordinateBtn, mEmailBtn;
    private JRadioButton mUrlBtn, mManualBtn;
    private JTextField mEmailText;
    private JTextField mUrlText;
    private static final String PANELNAME = "CACERTWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WICACertPage() {
        super(PANELNAME);
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        return true;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    @Override
    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea desc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERTWIZARD_TEXT_HEADING_LABEL"), 80), 1, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        mSelfBtn = makeJRadioButton("SELF", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSelfBtn, gbc);

        mSubordinateBtn = makeJRadioButton("SUBORDINATE", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSubordinateBtn, gbc);

        JTextArea desc1 = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERTWIZARD_TEXT_HEADING1_LABEL"), 80), 2, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc1, gbc);

        mEmailBtn = makeJRadioButton("EMAIL", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mEmailBtn, gbc);

        mEmailText = makeJTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mEmailText, gbc);

        mUrlBtn = makeJRadioButton("URL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mUrlBtn, gbc);

        mUrlText = makeJTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.fill = GridBagConstraints.NONE;
        add(mUrlText, gbc);

        mManualBtn = makeJRadioButton("MANUAL", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mManualBtn, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);

        ButtonGroup CAButtonGrp = new ButtonGroup();
        CAButtonGrp.add(mSelfBtn);
        CAButtonGrp.add(mSubordinateBtn);

        ButtonGroup MethodButtonGrp = new ButtonGroup();
        MethodButtonGrp.add(mEmailBtn);
        MethodButtonGrp.add(mUrlBtn);
        MethodButtonGrp.add(mManualBtn);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}
