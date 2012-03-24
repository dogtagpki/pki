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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.install.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.util.*;

/**
 * Certificate wizard request result page
 *
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
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

    public boolean isLastPage() {
        return false;
    }

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

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
		return true;
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        mDesc = createTextArea(mResource.getString(
		mPanelName+"_TEXT_DESC_LABEL"));
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

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent event) {
	}
}
