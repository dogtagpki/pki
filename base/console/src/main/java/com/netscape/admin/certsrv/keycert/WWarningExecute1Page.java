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
import java.awt.event.ActionEvent;

import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;

/**
 * Introduction page for certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated
class WWarningExecute1Page extends WizardBasePanel implements IWizardPanel {
    private JButton mAgree;
    private boolean mIsAgree = false;
    private static final String PANELNAME = "WARNINGEXECUTE1WIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WWarningExecute1Page() {
        super(PANELNAME);
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(CertSetupWizardInfo.REQUESTTYPE) &&
          wizardInfo.isNewKey() &&
          wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT) &&
          wizardInfo.getCAType().equals(CertSetupWizardInfo.SUBORDINATE_CA))
        return true;

        return false;
    }

    @Override
    public boolean validatePanel() {
        if (mIsAgree)
            return true;
        else {
            setErrorMessage("PROCEED");
            return false;
        }
    }

    @Override
    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = wizardInfo.getNameValuePairs();
        try {
            NameValuePairs response = connection.process(
              DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_CERT_REQUEST,
              wizardInfo.getCertType(), nvps);
            for (String key : response.keySet()) {
                String value = response.get(key);
                if (key.equals(Constants.PR_CSR)) {
                    wizardInfo.addEntry(Constants.PR_CSR, value);
                    break;
                }
            }
        } catch (EAdminException e) {
            setErrorMessage(e.toString());
            return false;
        }
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

        Icon icon = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON);

        JLabel label = new JLabel(icon);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(label, gbc);

        JTextArea desc = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "WARNINGEXECUTE1WIZARD_TEXT_DESC_LABEL"), 80), 3, 80);

        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        JTextArea desc1 = new JTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "WARNINGEXECUTE1WIZARD_LABEL_WARNING_LABEL"), 60), 3, 60);
        desc1.setBackground(getBackground());
        desc1.setEditable(false);
        desc1.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(desc1, gbc);

        mAgree = makeJButton("OK");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mAgree, gbc);

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mAgree)) {
            mIsAgree = true;
        }
    }
}
