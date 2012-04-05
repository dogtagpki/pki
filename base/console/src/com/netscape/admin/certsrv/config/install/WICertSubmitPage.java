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
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICertSubmitPage extends WizardBasePanel implements IWizardPanel {
    protected JRadioButton mSelfButton;
    protected JRadioButton mSubordinateButton;
    protected JTextArea mLabel;
    protected String mHelpIndex;
    private String mPanelName;
    protected InstallWizardInfo mWizardInfo;

    WICertSubmitPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));
        mWizardInfo = (InstallWizardInfo)info;
        if (!mWizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT)) {
            if (mWizardInfo.isCACertRequestDone() &&
              !mWizardInfo.isCACertInstalledDone()) {
                mSubordinateButton.setSelected(true);
                mSelfButton.setSelected(false);
            }
        }
        return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        mLabel = createTextArea(mResource.getString(
          mPanelName+"_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mLabel, gbc);

        mSelfButton = makeJRadioButton("SELF", true);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSelfButton, gbc);

        mSubordinateButton = makeJRadioButton("SUB", false);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSubordinateButton, gbc);

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(mSelfButton);
        buttonGroup.add(mSubordinateButton);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent e) {
        if (!mWizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT)) {
            if (e.getSource().equals(mSelfButton)) {
                if (mWizardInfo.isCACertRequestDone() &&
                  !mWizardInfo.isCACertInstalledDone()) {
                    String errorMsg = mResource.getString(mPanelName+"_LABEL_INCOMPLETE_LABEL");
                    JOptionPane.showMessageDialog(mParent, errorMsg, "Warning",
                      JOptionPane.WARNING_MESSAGE,
                      CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON));
                    mSelfButton.setSelected(false);
                    mSubordinateButton.setSelected(true);
                }
            }
        }
    }
}
