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
package com.netscape.admin.certsrv.keycert;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;

/**
 * Request status page for certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated
class WRequestStatusPage extends WizardBasePanel implements IWizardPanel {
    private static final String PANELNAME = "REQUESTSTATUSWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-certrequeststatus-help";
    protected JTextArea mDesc;

    protected String mRequestId;

    WRequestStatusPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WRequestStatusPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(PANELNAME));
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

		if (!wizardInfo.requestSent()) {
			String str = "";
			if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.REQUESTTYPE) &&
				(!wizardInfo.getCAType().equals(CertSetupWizardInfo.SELF_SIGNED))) {
				str = mResource.getString(
							"REQUESTSTATUSWIZARD_TEXT_REQUEST_LABEL");
				mDesc.setText(str);
				return true;
			}
			return false;
		} else {
			String status = wizardInfo.getRequestStatus();
			String str = wizardInfo.getRequestID();
			String error = wizardInfo.getRequestError();

			if (str != null && !str.equals("")) {
				if (status != null && status.equals("5")) {
					// rejected
					mDesc.setText(mResource.getString("REQUESTRESULTWIZARD_TEXT_REJECT_LABEL") + error + "\n\n"+ mResource.getString("REQUESTRESULTWIZARD_TEXT_ID_LABEL") + str + mResource.getString("REQUESTRESULTWIZARD_TEXT_REJECTEND_LABEL"));
				} else {
					// success
					mDesc.setText(mResource.getString("REQUESTRESULTWIZARD_TEXT_DESC_LABEL") +
                    mResource.getString("REQUESTRESULTWIZARD_TEXT_ID_LABEL") + str +
                    mResource.getString("REQUESTRESULTWIZARD_TEXT_END_LABEL"));
				}
			}
			else if (error != null)
				mDesc.setText(error);
			else
				mDesc.setText(mResource.getString("REQUESTRESULTWIZARD_TEXT_DESC_LABEL") +
                mResource.getString("REQUESTRESULTWIZARD_TEXT_NOID_LABEL"));
		}
        return true;
    }

    @Override
    public boolean isLastPage() {
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

        mDesc = createTextArea(" ");
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
    public void getUpdateInfo(WizardInfo info) {
    }
}
