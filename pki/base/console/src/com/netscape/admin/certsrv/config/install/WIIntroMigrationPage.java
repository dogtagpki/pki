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

/**
 * Data Migration.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIIntroMigrationPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mYes;
    private JRadioButton mNo;
    private static final String PANELNAME = "INTROMIGRATIONWIZARD";
    private String mHelpIndex;
    private static final String CAHELPINDEX = 
      "install-ca-migration-enable-wizard-help";
    private static final String CAKRAHELPINDEX = 
      "install-cakra-migration-enable-wizard-help";
    
    WIIntroMigrationPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIIntroMigrationPage(JDialog parent, JFrame adminFrame) {
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
        if (!wizardInfo.isCAInstalled() || wizardInfo.isMigrationDone())
            return false;
        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;   
        else
            mHelpIndex = CAHELPINDEX;
        setBorder(makeTitledBorder(PANELNAME));
        return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        Hashtable data = new Hashtable();

        boolean ready = false;
        if (mYes.isSelected()) {
            wizardInfo.setEnableMigration(ConfigConstants.TRUE);
            data.put(ConfigConstants.TASKID, TaskId.TASK_TOKEN_INFO);
            data.put(ConfigConstants.OPTYPE, OpDef.OP_READ);
        } else {
            wizardInfo.setEnableMigration(ConfigConstants.FALSE);
            // do the data migration
            data.put(ConfigConstants.TASKID, TaskId.TASK_MIGRATION);
            data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
            data.put(ConfigConstants.PR_ENABLE_MIGRATION, 
              ConfigConstants.FALSE);
        }

        startProgressStatus();

        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        }

        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea label = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_DESC_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(label, gbc);

        mYes = makeJRadioButton("YES", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mYes, gbc);
 
        mNo = makeJRadioButton("NO", true);        
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        add(mNo, gbc);

        ButtonGroup group = new ButtonGroup();
        group.add(mYes);
        group.add(mNo);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}

