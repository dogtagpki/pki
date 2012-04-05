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
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * KRA Key recovery for installation wizard: specify number of required and
 * available agents
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKRAScheme1Page extends WizardBasePanel implements IWizardPanel {
    private JTextField mRequiredText;
    private JTextField mAvailText;
    private String mHelpIndex;
    private static final String PANELNAME = "KRASCHEME1WIZARD";
    private static final String KRAHELPINDEX =
      "install-kra-mnscheme-wizard-help";
    private static final String CAKRAHELPINDEX =
      "install-cakra-mnscheme-wizard-help";
    private static final String RAKRAHELPINDEX =
      "install-rakra-mnscheme-wizard-help";
    private int mRequired, mAvail;

    WIKRAScheme1Page(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIKRAScheme1Page(JDialog parent, JFrame adminFrame) {
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
        if (!wizardInfo.doKeySplitting())
           return false;
        if (wizardInfo.isCloning())
           return false;
        if (!wizardInfo.isKRAInstalled() || wizardInfo.isKRANMSchemeDone())
            return false;
        setBorder(makeTitledBorder(PANELNAME));
        mRequiredText.setText(wizardInfo.getRequiredAgents());
        mAvailText.setText(wizardInfo.getTotalAgents());

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = KRAHELPINDEX;
        return true;
    }

    public boolean validatePanel() {
        String str = mRequiredText.getText().trim();
        if (str.equals("")) {
            setErrorMessage("CANNOTBEBLANK");
            return false;
        }

        try {
            mRequired = Integer.parseInt(str);
            str = mAvailText.getText().trim();
            if (str.equals("")) {
                setErrorMessage("CANNOTBEBLANK");
                return false;
            }
            mAvail = Integer.parseInt(str);
        } catch (NumberFormatException e) {
            setErrorMessage("NOTINTEGER");
            return false;
        }

        if (mRequired <= 0 || mAvail <= 0) {
            setErrorMessage("NONZERO");
            return false;
        }

        if (mRequired > mAvail) {
            setErrorMessage("LARGER");
            return false;
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel requiredLbl = makeJLabel("REQUIRED");
        gbc.anchor = gbc.NORTHEAST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(requiredLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mRequiredText = makeJTextField(5);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mRequiredText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea dummy = createTextArea(" ", 1, 15);
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel availLbl = makeJLabel("AVAILABLE");
        gbc.anchor = gbc.NORTHEAST;
        gbc.insets = new Insets(0,COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.weighty = 1.0;
        gbc.fill = gbc.NONE;
        add(availLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mAvailText = makeJTextField(5);
        gbc.insets = new Insets(0,COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weighty = 1.0;
        gbc.fill = gbc.NONE;
        add(mAvailText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea dummy1 = createTextArea(" ", 1, 15);
        gbc.weighty = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy1, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        wizardInfo.setRequiredAgents(mRequiredText.getText().trim());
        wizardInfo.setTotalAgents(mAvailText.getText());
    }
}
