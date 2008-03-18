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
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
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

    public boolean isLastPage() {
        return false;
    }

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
                String str = (String)tokenizer.nextToken();
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

    public boolean validatePanel() {
        return true;
    }

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
            rawData = rawData+"&"+ConfigConstants.PR_CMS_SEED+"="+
              (new Long(WizardBasePanel.mSeed).toString());

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

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea desc = createTextArea(mResource.getString(
          "INTROINSTALLWIZARD_TEXT_DESC_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mLabel = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "INTROINSTALLWIZARD_TEXT_HEADING_LABEL"), 80), 2, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mLabel, gbc);

        mDbButton = makeJRadioButton("CREATEDB");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mDbButton, gbc);

        mNetworkButton = makeJRadioButton("NETWORK");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mNetworkButton, gbc);

        mAdminButton = makeJRadioButton("ADMIN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mAdminButton, gbc);

        mSubsystemButton = makeJRadioButton("SUBSYSTEMS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSubsystemButton, gbc);

        mMigrationButton = makeJRadioButton("MIGRATION");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mMigrationButton, gbc);

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
}
