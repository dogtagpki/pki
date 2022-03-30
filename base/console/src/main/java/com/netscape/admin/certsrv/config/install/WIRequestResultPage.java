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
import java.awt.event.ActionEvent;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;

/**
 * Certificate wizard request result page
 *
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class WIRequestResultPage extends WizardBasePanel implements IWizardPanel {
    private static final String PANELNAME = "REQUESTRESULTWIZARD";
    private static final String HELPINDEX =
      "install-request-result-wizard-help";

    protected String mPanelName = PANELNAME;
    protected String mHelpIndex = HELPINDEX;
    protected JTextArea mDesc;
    protected boolean print2RequestIDs = false;

    protected String mRequestId;

    WIRequestResultPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIRequestResultPage(JDialog parent, JFrame adminFrame) {
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

		if (!wizardInfo.requestSent())
			return false;

        setBorder(makeTitledBorder(PANELNAME));

		String status = wizardInfo.getX509RequestStatus();
        String str = wizardInfo.getX509RequestID();
		String error = wizardInfo.getX509RequestError();

        if (str != null && !str.equals("")) {
            if (status != null && status.equals(Constants.PR_REQUEST_REJECTED)) {
                // rejected
                mDesc.setText(mResource.getString(mPanelName+"_TEXT_REJECT_LABEL") +
                error + "\n\n"+ mResource.getString(mPanelName+"_TEXT_ID_LABEL") + str +
                mResource.getString(mPanelName+"_TEXT_REJECTEND_LABEL"));
            } else {
                mDesc.setText(mResource.getString(mPanelName+"_TEXT_DESC_LABEL") +
                  mResource.getString(mPanelName+"_TEXT_ID_LABEL") + str +
                  mResource.getString(mPanelName+"_TEXT_END_LABEL"));
            }
        } else if (error != null && !error.equals(""))
            mDesc.setText(error);
        else
            mDesc.setText(mResource.getString(mPanelName+"_TEXT_DESC_LABEL") +
              mResource.getString(mPanelName+"_TEXT_NOID_LABEL"));

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
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        mDesc = createTextArea(mResource.getString(
		mPanelName+"_TEXT_DESC_LABEL"));
        //mDesc = createTextArea("request id");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mDesc, gbc);

        JLabel label = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(label, gbc);

        super.init();
    }

    @Override
    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }

    @Override
    public void actionPerformed(ActionEvent event) {
	}
}
