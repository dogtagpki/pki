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
 * This page is to install the certificate in the internal token. It
 * displays the certificate information.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIInstallCert2Page extends WizardBasePanel implements IWizardPanel {
    private JButton mAdd;
    private static final String PANELNAME = "INSTALLCERT2WIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";

    WIInstallCert2Page() {
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

        JLabel subjectDNLbl = makeJLabel("SUBJECTDN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(subjectDNLbl, gbc);

        JLabel issuerLbl = makeJLabel("ISSUE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(issuerLbl, gbc);

        JTextArea subjectText = new JTextArea(null, null, 0, 0);
        JScrollPane subjectScrollPane = new JScrollPane(subjectText,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        //subjectScrollPane.setPreferredSize(new Dimension(50, 30));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE, 0 );
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        gbc.fill = gbc.BOTH;
        add(subjectScrollPane, gbc);

        JTextArea issueText = new JTextArea(null, null, 0, 0);
        JScrollPane issueScrollPane = new JScrollPane(issueText,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        //issueScrollPane.setPreferredSize(new Dimension(50, 30));
        CMSAdminUtil.resetGBC(gbc);
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = gbc.REMAINDER;
        add(issueScrollPane, gbc);

        JTextArea infoText = new JTextArea(null, null, 0, 0);
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        infoText.setPreferredSize(new Dimension(50, 20));
        gbc.fill = gbc.BOTH;
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(infoText, gbc);

        mAdd = makeJButton("ADD");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mAdd, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
