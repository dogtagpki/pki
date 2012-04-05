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
class WIAllCertsInstalledPage extends WizardBasePanel implements IWizardPanel {
    private JTextArea mLabel;
    private static final String PANELNAME = "ALLCERTSINSTALLEDWIZARD";
    private static final String HELPINDEX =
      "install-allcerts-getinstalled-wizard-help";

    WIAllCertsInstalledPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIAllCertsInstalledPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return true;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        if (wizardInfo.isCloning())
            return false;

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled()) {
            if (caCertInstalled(wizardInfo) && kraCertInstalled(wizardInfo))
                return false;
            if (wizardInfo.isCloning()) {
                if (wizardInfo.isCACloningDone() && wizardInfo.isKRACloningDone()) {
                    if (wizardInfo.isSSLCloningDone())
                        return false;
                    else if (!wizardInfo.isSSLCloningDone()) {
                        if (wizardInfo.isSSLLocalCertDone() || wizardInfo.isSSLCertInstalledDone())
                            return false;
                    }
                }
            }
        }

        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled()) {
            if (raCertInstalled(wizardInfo) && kraCertInstalled(wizardInfo))
                return false;
            if (wizardInfo.isCloning()) {
                if (wizardInfo.isRACloningDone() && wizardInfo.isKRACloningDone()) {
                    if (wizardInfo.isSSLCloningDone())
                        return false;
                    else if (!wizardInfo.isSSLCloningDone()) {
                        if (wizardInfo.isSSLLocalCertDone() || wizardInfo.isSSLCertInstalledDone())
                            return false;
                    }
                }
            }
        }

        else if (wizardInfo.isCAInstalled()) {
            if (caCertInstalled(wizardInfo))
                return false;
            if (wizardInfo.isCloning()) {
                if (wizardInfo.isCACloningDone()) {
                    if (wizardInfo.isSSLCloningDone())
                        return false;
                    else if (!wizardInfo.isSSLCloningDone()) {
                        if (wizardInfo.isSSLLocalCertDone() || wizardInfo.isSSLCertInstalledDone())
                            return false;
                    }
                }
            }
        }
        else if (wizardInfo.isOCSPInstalled()) {
            if (ocspCertInstalled(wizardInfo))
                return false;
        }

        else if (wizardInfo.isRAInstalled()) {
            if (raCertInstalled(wizardInfo))
                return false;
            if (wizardInfo.isCloning()) {
                if (wizardInfo.isRACloningDone()) {
                    if (wizardInfo.isSSLCloningDone())
                        return false;
                    else if (!wizardInfo.isSSLCloningDone()) {
                        if (wizardInfo.isSSLLocalCertDone() || wizardInfo.isSSLCertInstalledDone())
                            return false;
                    }
                }
            }
        }

        else if (wizardInfo.isKRAInstalled()) {
            if (kraCertInstalled(wizardInfo))
                return false;
            if (wizardInfo.isCloning()) {
                if (wizardInfo.isKRACloningDone()) {
                    if (wizardInfo.isSSLCloningDone())
                        return false;
                    else if (!wizardInfo.isSSLCloningDone()) {
                        if (wizardInfo.isSSLLocalCertDone() || wizardInfo.isSSLCertInstalledDone())
                            return false;
                    }
                }
            }
        }
        else if (wizardInfo.isTKSInstalled()) {
            if (tksCertInstalled(wizardInfo))
                return false;
        }
        setBorder(makeTitledBorder(PANELNAME));
        mLabel.setVisible(false);

        return true;
    }

    private boolean caCertInstalled(InstallWizardInfo wizardInfo) {
        if (wizardInfo.isMigrationEnable() ||
          ((wizardInfo.isSelfSignedCACertDone() ||
          wizardInfo.isCACertInstalledDone()) &&
          (wizardInfo.isSSLLocalCertDone() || wizardInfo.isSSLCertInstalledDone())))
            return true;
        return false;
    }

    private boolean ocspCertInstalled(InstallWizardInfo wizardInfo) {
        if (wizardInfo.isOCSPCertInstalledDone() &&
           wizardInfo.isSSLCertInstalledDone())
            return true;
        return false;
    }

    private boolean raCertInstalled(InstallWizardInfo wizardInfo) {
        if ((wizardInfo.isRALocalCertDone() ||
          wizardInfo.isRACertInstalledDone()) &&
          (wizardInfo.isMigrationEnable() || wizardInfo.isSSLLocalCertDone() ||
           wizardInfo.isSSLCertInstalledDone()))
            return true;
        return false;
    }

    private boolean kraCertInstalled(InstallWizardInfo wizardInfo) {
        if ((wizardInfo.isKRALocalCertDone() ||
          wizardInfo.isKRACertInstalledDone()) &&
          (wizardInfo.isMigrationEnable() || wizardInfo.isSSLLocalCertDone() ||
           wizardInfo.isSSLCertInstalledDone()))
            return true;
        return false;
    }
    private boolean tksCertInstalled(InstallWizardInfo wizardInfo) {
        if(wizardInfo.isSSLCertInstalledDone())
            return true;
        return false;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_GET_DEFAULT_INFO;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
        // #344791 - help server to make up the hostname
/*
        data.put(ConfigConstants.PR_HOST,
          consoleInfo.get(ConfigConstants.PR_HOST));
*/
        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
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

        JTextArea desc = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_DESC_LABEL"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mLabel = createTextArea(mResource.getString(
            "INTROINSTALLWIZARD_TEXT_HEADING_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mLabel, gbc);

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
    }
}
