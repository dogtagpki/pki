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

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIRecreateDBPage extends WizardBasePanel implements IWizardPanel {
    protected JRadioButton mYes;
    protected JRadioButton mNo;
    protected JTextArea mLabel;
    private static final String PANELNAME = "INSTALLDBAGAIN";
    private static final String HELPINDEX = 
      "install-internaldb-createdbagain-help";
    
    WIRecreateDBPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIRecreateDBPage(JDialog parent, JFrame adminFrame) {
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
        if (wizardInfo.isCloning())
            return false;
        if (wizardInfo.isDBCreated()) {
            setBorder(makeTitledBorder(PANELNAME));
            return true; 
        }
      
        return false;
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

        CMSAdminUtil.resetGBC(gbc);
        mLabel = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mLabel, gbc);

        mYes = makeJRadioButton("YES", false);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mYes, gbc);

        mNo = makeJRadioButton("NO", true);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE, 
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mNo, gbc);

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(mYes);
        buttonGroup.add(mNo);

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
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mYes.isSelected()) {
            wizardInfo.setDBCreateNow(ConfigConstants.TRUE);
        } else {
            wizardInfo.setDBCreateNow(ConfigConstants.FALSE);
        }
    }
}
