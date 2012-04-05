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
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIMasterOrClone extends WizardBasePanel implements IWizardPanel {
    protected JRadioButton mYes;
    protected JRadioButton mNo;
    protected JTextArea mLabel;
    private static final String PANELNAME = "MASTERORCLONE";
    private static final String HELPINDEX =
      "install-internaldb-createdbagain-help";

    WIMasterOrClone(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIMasterOrClone(JDialog parent, JFrame adminFrame) {
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
        if(wizardInfo.isCloning()) {
            mYes.setSelected(true);
            mNo.setSelected(false);
        }else{
            mYes.setSelected(false);
            mNo.setSelected(true);
        }
        if(wizardInfo.isClonePageDone())
            return false;
        else
            return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        cleanUpWizardInfo(wizardInfo);
        startProgressStatus();
        Debug.println("WIMasterOrClone:concludePanel() 1");
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_MASTER_OR_CLONE;
        rawData = rawData+"&"+ ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
         if (mYes.isSelected()) {
             rawData = rawData+"&"+"cloning="+ConfigConstants.TRUE;
        } else {
             rawData = rawData+"&"+"cloning="+ConfigConstants.FALSE;
             rawData = rawData+"&"+ConfigConstants.PR_CLONE_SETTING_DONE+"="+ConfigConstants.TRUE;
        }
        rawData = rawData+"&"+ConfigConstants.PR_CMS_SEED+"="+(new Long(WizardBasePanel.mSeed).toString());
        Debug.println("WIMasterOrClone:concludePanel() 2");
        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str == null)
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }else if (!mYes.isSelected()){
            wizardInfo.setClonePageDone(ConfigConstants.TRUE);
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

        CMSAdminUtil.resetGBC(gbc);
        mLabel = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mLabel, gbc);


        mYes = makeJRadioButton("YES", false);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mYes, gbc);

        mNo = makeJRadioButton("NO", false);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mNo, gbc);

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(mYes);
        buttonGroup.add(mNo);

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
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mYes.isSelected()) {
            wizardInfo.setCloning(ConfigConstants.TRUE);
        } else {
            wizardInfo.setCloning(ConfigConstants.FALSE);
        }
    }
}
