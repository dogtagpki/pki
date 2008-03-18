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

/**
 * Introduction page for certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.keycert
 */
class WIntroPage extends WizardBasePanel implements IWizardPanel {
    private static final String PANELNAME = "INTROKEYCERTWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-introduction-help";
    
    WIntroPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIntroPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(PANELNAME));
        return true; 
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        startProgressStatus();
        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();
        nvps.add(Constants.PR_TOKEN_LIST, "");
        try {
            NameValuePairs response = connection.read(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_TOKEN, Constants.RS_ID_CONFIG, nvps);
            for (int i=0; i<response.size(); i++) {
                NameValuePair nvp = response.elementAt(i);
                String name = nvp.getName();
                if (name.equals(Constants.PR_TOKEN_LIST))
                    wizardInfo.addEntry(name, nvp.getValue());
            }
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
            endProgressStatus();
            return false;
        }
        endProgressStatus();
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

/*
        JTextArea desc = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "INTROKEYCERTWIZARD_TEXT_DESC_LABEL"), 80), 2, 80);
*/
        JTextArea desc = createTextArea(mResource.getString(
          "INTROKEYCERTWIZARD_TEXT_DESC_LABEL"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
