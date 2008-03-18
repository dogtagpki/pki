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

import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.install.*;

/**
 * Request status page for certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.keycert
 */
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

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(PANELNAME));
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;

		if (!wizardInfo.requestSent()) {
			String str = "";
			if (wizardInfo.getOperationType().equals(wizardInfo.REQUESTTYPE) &&
				(!wizardInfo.getCAType().equals(wizardInfo.SELF_SIGNED))) {
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

    public boolean isLastPage() {
        return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        mDesc = createTextArea(" ");
        //mDesc = createTextArea("request id");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mDesc, gbc);

        JLabel label = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(label, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
