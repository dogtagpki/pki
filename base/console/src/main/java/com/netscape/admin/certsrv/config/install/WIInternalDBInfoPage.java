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

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;

/**
 * This panel asks for the information of the current internal database.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
class WIInternalDBInfoPage extends WizardBasePanel implements IWizardPanel {
    private JTextField mBindAsText;
    private JPasswordField mPasswordText;
    private JLabel mBindAsLabel, mPasswordLabel;

    private static final String PANELNAME = "INTERNALDBINFOWIZARD";
    private static final String HELPINDEX =
      "install-internaldb-logon-wizard-help";

    WIInternalDBInfoPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIInternalDBInfoPage(JDialog parent, JFrame adminFrame) {
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
        if (wizardInfo.getInternalDBPasswd() != null)
            return false;
        setBorder(makeTitledBorder(PANELNAME));
        mBindAsText.setText(wizardInfo.getDBBindDN());
        return true;
    }

    @Override
    public boolean validatePanel() {
        String passwd = mPasswordText.getText();
        if (passwd.equals("")) {
            setErrorMessage("BLANKPASSWD");
            return false;
        }

        return true;
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        wizardInfo.setDBBindDN(mBindAsText.getText().trim());
        wizardInfo.setInternalDBPasswd(mPasswordText.getText().trim());

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_VALIDATE_DSPASSWD;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+wizardInfo.getInternalDBPasswd();
        rawData = rawData+"&"+ConfigConstants.PR_DB_BINDDN+"="+wizardInfo.getDBBindDN();

        startProgressStatus();

        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str.equals(""))
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

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mBindAsLabel = makeJLabel("ADMIN");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mBindAsLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mBindAsText = makeJTextField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mBindAsText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordLabel = makeJLabel("PWD");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mPasswordText = makeJPasswordField(30);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        // gbc.fill = gbc.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mPasswordText, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}
