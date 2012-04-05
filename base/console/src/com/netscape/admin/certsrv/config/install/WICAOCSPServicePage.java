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
import java.math.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * This panel asks for the starting serial number that the CA issues
 *
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICAOCSPServicePage extends WizardBasePanel implements IWizardPanel {
    private JTextArea mDesc;

    private boolean mEnable;
    private JCheckBox mOCSPServiceCB;
    private JLabel mOCSPServiceLabel;

    private static final String PANELNAME = "CAOCSPSERVICEWIZARD";
    private static final String HELPINDEX =
      "install-ca-ocspservice-wizard-help";

    WICAOCSPServicePage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WICAOCSPServicePage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
		String serial;
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        setBorder(makeTitledBorder(PANELNAME));
		// If ca's signing cert is not generated,
		// we allow "back" to modify the panel
        if (!wizardInfo.isCAInstalled())
            return false;
        if (wizardInfo.isOCSPServiceDone())
            return false;
        if (wizardInfo.isOCSPInstalled())
            return false;

	mDesc.setText(mResource.getString(PANELNAME+"_TEXT_HEADING_LABEL"));

        return true;
    }

    public boolean validatePanel()
    {
        mEnable = mOCSPServiceCB.isSelected();
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_ADD_OCSP_SERVICE;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
	if (mEnable)
            rawData = rawData+"&"+ConfigConstants.PR_CA_OCSP_SERVICE+"="+
              "true";
	else
            rawData = rawData+"&"+ConfigConstants.PR_CA_OCSP_SERVICE+"="+
              "false";

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

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        mDesc = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mDesc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mOCSPServiceLabel = makeJLabel("OCSPSERVICE");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mOCSPServiceLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mOCSPServiceCB = makeJCheckBox("OCSPSERVICE");
        mOCSPServiceCB.setSelected(true);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mOCSPServiceCB, gbc);

       JLabel dummy = new JLabel(" ");
       CMSAdminUtil.resetGBC(gbc);
       gbc.anchor = gbc.NORTHWEST;
       gbc.gridwidth = gbc.REMAINDER;
       gbc.gridheight = gbc.REMAINDER;
       gbc.weighty = 1.0;
       add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
	if (mEnable)
	  wizardInfo.setOCSPService(ConfigConstants.TRUE);
	else
	  wizardInfo.setOCSPService(ConfigConstants.FALSE);
    }
}
