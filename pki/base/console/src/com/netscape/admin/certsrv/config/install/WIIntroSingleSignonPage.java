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

import java.io.*;
import java.net.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.comm.*;
import com.netscape.management.client.util.*;

/**
 * Setup Single Signon for the installation wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WIIntroSingleSignonPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mYes;
    private JRadioButton mNo;
    private static final String HELPINDEX =
      "install-single-signon-enable-wizard-help";
    private static final String PANELNAME = "INSTALLINTROSINGLESIGNON";

    WIIntroSingleSignonPage() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(PANELNAME));

        return true; 
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        if (mNo.isSelected()) {
            InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
            Hashtable data = new Hashtable();
            ConsoleInfo consoleInfo = wizardInfo.getAdminConsoleInfo();
            CMSConfigCert configCertCgi = new CMSConfigCert();
            configCertCgi.initialize(wizardInfo);
            data.put(ConfigConstants.TASKID, TaskId.TASK_MISCELLANEOUS);
            data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
            data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
              consoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));
            data.put(ConfigConstants.PR_ADMIN_PASSWD,
              (String)consoleInfo.get(ConfigConstants.PR_ADMIN_PASSWD));
            
            boolean ready = configCertCgi.configCert(data);
            return ready;
        }

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
        JTextArea heading = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            PANELNAME+"_TEXT_HEADING_LABEL"), 80), 1, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(heading, gbc);
*/
        JLabel heading = makeJLabel("HEADING");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(heading, gbc);

        mNo = makeJRadioButton("NO", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mNo, gbc);
  
        mYes = makeJRadioButton("YES", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0,COMPONENT_SPACE, 
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mYes, gbc);
 
        JLabel dummy = new JLabel("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(dummy, gbc);
        
        ButtonGroup buttonGrp = new ButtonGroup();
        buttonGrp.add(mYes);
        buttonGrp.add(mNo);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mNo.isSelected())
            wizardInfo.put(ConfigConstants.PR_SINGLE_SIGNON, ConfigConstants.FALSE);
        else
            wizardInfo.put(ConfigConstants.PR_SINGLE_SIGNON, ConfigConstants.TRUE);
    }
}
