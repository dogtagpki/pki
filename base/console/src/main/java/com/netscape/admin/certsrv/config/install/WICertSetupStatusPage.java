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
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;
import javax.swing.*;
import com.netscape.management.client.*;

/**
 * Status page for the configuration of the certificate server.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICertSetupStatusPage extends WizardBasePanel implements IWizardPanel {
    private JTextArea desc;
    private static final String PANELNAME = "INSTALLCONFIGSTATUSWIZARD";
    private static final String HELPINDEX = "install-certsetup-status-wizard-help";

    WICertSetupStatusPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WICertSetupStatusPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    @Override
    public boolean isLastPage() {
        return true;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String str = "";
        if (wizardInfo.isCAInstalled()) {

            String str1 = "";
			// display status
            str = mResource.getString(
              "INSTALLCONFIGSTATUSWIZARD_CATEXT_DESC_LABEL");
            if (wizardInfo.isKRAInstalled())
                str1 = mResource.getString(
                  "INSTALLCONFIGSTATUSWIZARD_CAKRATEXT_DESC_LABEL");
            String link = "https://"+wizardInfo.getMachineName()+":"+
              wizardInfo.getAdminPort() + "/ca/adminEnroll.html";
            desc.setText(str+"\n"+link+"\n\n"+str1);
        } else if (wizardInfo.isOCSPInstalled()) {
                desc.setText(mResource.getString(
                   "INSTALLCONFIGSTATUSWIZARD_OCSPTEXT_DESC_LABEL"));
        } else if (wizardInfo.isRAInstalled()) {
            if (wizardInfo.isKRAInstalled())
                desc.setText(mResource.getString(
                   "INSTALLCONFIGSTATUSWIZARD_RAKRATEXT_DESC_LABEL"));
            else
                desc.setText(mResource.getString(
                   "INSTALLCONFIGSTATUSWIZARD_RATEXT_DESC_LABEL"));
        } else if (wizardInfo.isKRAInstalled()) {
            desc.setText(mResource.getString(
               "INSTALLCONFIGSTATUSWIZARD_KRATEXT_DESC_LABEL"));
        }
		else if (wizardInfo.isTKSInstalled()) {
            desc.setText(mResource.getString(
               "INSTALLCONFIGSTATUSWIZARD_TKSTEXT_DESC_LABEL"));
        }
        setBorder(makeTitledBorder(PANELNAME));

        CMSAdmin admin = (CMSAdmin)wizardInfo.get("CMSAdmin");
        IPage viewInstance = (IPage)wizardInfo.get("viewInstance");
        if (viewInstance != null)
            admin.updateMenu(viewInstance);
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

/*
        desc = new JTextArea("", 4, 80);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
*/
        desc = createTextArea("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        add(desc, gbc);
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}

