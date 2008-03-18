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
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIDBEnrollPage extends WizardBasePanel implements IWizardPanel {
    private JCheckBox mEnable;
    private JTextField mHostNameText, mPortText, mBaseDNText;
    private JComboBox mVersionBox;

    private static final String PANELNAME = "DBENROLLWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WIDBEnrollPage() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
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

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "DBENROLLWIZARD_TEXT_HEADING_LABEL"), 80), 1, 80);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mEnable = makeJCheckBox("ENABLE");
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mEnable, gbc);

        JPanel panel = new JPanel();
        panel.setBorder(CMSAdminUtil.makeTitledBorder(mResource,
          PANELNAME, "DESTINATION"));
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(panel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel hostName = makeJLabel("HOST");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        panel.add(hostName, gbc);
        
        CMSAdminUtil.resetGBC(gbc);
        mHostNameText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        panel.add(mHostNameText, gbc);
        
/*
        CMSAdminUtil.resetGBC(gbc);
        JTextArea dummy = createTextArea(" ", 2, 5);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(dummy, gbc);
*/

        CMSAdminUtil.resetGBC(gbc);
        JLabel portNumber = makeJLabel("PORT");        
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel.add(portNumber, gbc);
 
        CMSAdminUtil.resetGBC(gbc);
        mPortText = makeJTextField(10);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel.add(mPortText, gbc);
 
        CMSAdminUtil.resetGBC(gbc);
        JLabel versionLbl = makeJLabel("VERSION");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel.add(versionLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mVersionBox = makeJComboBox("VERSION");
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel.add(mVersionBox, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy = new JLabel(" ");
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel.add(dummy, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel baseDNLbl = makeJLabel("BASEDN");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel.add(baseDNLbl, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mBaseDNText = makeJTextField(20);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        panel.add(mBaseDNText, gbc);

/*
        CMSAdminUtil.resetGBC(gbc);
        JTextArea dummy1 = createTextArea(" ", 2, 30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy1, gbc);
*/

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
