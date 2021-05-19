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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.StringTokenizer;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIIntroPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mDbButton;
    private JRadioButton mNetworkButton;
    private JRadioButton mAdminButton;
    private JRadioButton mSubsystemButton;
    private JRadioButton mMigrationButton;
    private JTextArea mLabel;
    private static final String PANELNAME = "INTROINSTALLWIZARD";
    private static final String HELPINDEX =
      "install-general-intro-wizard-help";

    WIIntroPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIIntroPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        setBorder(makeTitledBorder(PANELNAME));
        mAdminFrame = wizardInfo.getAdminFrame();
        mLabel.setVisible(false);
        mDbButton.setVisible(false);
        mNetworkButton.setVisible(false);
        mAdminButton.setVisible(false);
        mSubsystemButton.setVisible(false);
        mMigrationButton.setVisible(false);
        String stages = wizardInfo.getStages();

        if (stages != null && !stages.equals("")) {
            StringTokenizer tokenizer = new StringTokenizer(stages, ":");
            mLabel.setVisible(true);
            while (tokenizer.hasMoreTokens()) {
                String str = tokenizer.nextToken();
                if (str.equals(ConfigConstants.STAGE_INTERNAL_DB)) {
                    mDbButton.setVisible(true);
                } else if (str.equals(ConfigConstants.STAGE_SETUP_PORTS)) {
                    mNetworkButton.setVisible(true);
                } else if (str.equals(ConfigConstants.STAGE_SETUP_ADMINISTRATOR)) {
                    mAdminButton.setVisible(true);
                }
            }
        }
        return true;
    }

    @Override
    public boolean validatePanel() {
        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        cleanUpWizardInfo(wizardInfo);

        startProgressStatus();
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_GET_DEFAULT_INFO;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+ OpDef.OP_READ;
        boolean ready = send(rawData, wizardInfo);
        if (ready) {
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_TOKEN_INFO;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
            rawData = rawData+"&"+ConfigConstants.PR_CMS_SEED+"="+Long.valueOf(WizardBasePanel.mSeed);

            ready = send(rawData, wizardInfo);
        }

        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str == null)
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }

        return ready;
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

        JTextArea desc = createTextArea(mResource.getString(
          "INTROINSTALLWIZARD_TEXT_DESC_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        mLabel = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "INTROINSTALLWIZARD_TEXT_HEADING_LABEL"), 80), 2, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mLabel, gbc);

        mDbButton = makeJRadioButton("CREATEDB");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mDbButton, gbc);

        mNetworkButton = makeJRadioButton("NETWORK");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mNetworkButton, gbc);

        mAdminButton = makeJRadioButton("ADMIN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mAdminButton, gbc);

        mSubsystemButton = makeJRadioButton("SUBSYSTEMS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSubsystemButton, gbc);

        mMigrationButton = makeJRadioButton("MIGRATION");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mMigrationButton, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        add(dummy, gbc);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}
