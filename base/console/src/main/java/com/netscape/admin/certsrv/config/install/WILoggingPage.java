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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WILoggingPage extends WizardBasePanel implements IWizardPanel {
    private JCheckBox mEnableSysLog;
    private JCheckBox mEnableErrorLog;
    private JCheckBox mEnableAuditLog;
    private JComboBox<String> mlogFQC, mLogLevel;
    private JTextField mlogMaxSizText, mlogBufSizText;
    private static final String PANELNAME = "LOGGINGWIZARD";
    private static final String HELPINDEX =
      "configuration-kra-wizard-change-keyscheme-help";
    private static final String EMPTYSTR = "                    ";

    protected final static int YEAR = 31536000;
    protected final static int MONTH = 2592000;
    protected final static int WEEK = 604800;
    protected final static int DAY = 86400;
    protected final static int HOUR = 3600;

    WILoggingPage() {
        super(PANELNAME);
        init();
    }

    @Override
    public boolean isLastPage() {
        return false;
    }

    @Override
    public boolean initializePanel(WizardInfo info) {

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

        CMSAdminUtil.resetGBC(gbc);
        mEnableSysLog = makeJCheckBox("SYSLOG");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mEnableSysLog, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mEnableErrorLog = makeJCheckBox("ERRORLOG");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mEnableErrorLog, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mEnableAuditLog = makeJCheckBox("AUDITLOG");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mEnableAuditLog, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel logFQC = makeJLabel("LOGFQC");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        add(logFQC, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mlogFQC = makeJComboBox("LOGFQC");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 0.0;
        add(mlogFQC, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea dummy1 = new JTextArea(EMPTYSTR, 1, 20);
        dummy1.setBackground(getBackground());
        dummy1.setEditable(false);
        dummy1.setCaretColor(getBackground());
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(dummy1, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel logMaxSiz = makeJLabel("LOGMAXSIZ");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        add(logMaxSiz, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mlogMaxSizText = makeJTextField(10);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        add(mlogMaxSizText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel maxLabel = makeJLabel("SIZEUNIT");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(maxLabel, gbc);
        //mActiveColor = mlogMaxSizText.getBackground();

        CMSAdminUtil.resetGBC(gbc);
        JLabel logBufSiz = makeJLabel("LOGBUFSIZ");
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        add(logBufSiz, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mlogBufSizText = makeJTextField(10);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        add(mlogBufSizText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel bufferLabel = makeJLabel("SIZEUNIT");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(bufferLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel logLevel = makeJLabel("LOGLEVEL");
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.NORTHEAST;
        add(logLevel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mLogLevel = makeJComboBox("LOGLEVEL");
        gbc.anchor = GridBagConstraints.NORTHWEST;
        add(mLogLevel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy4 = new JLabel(EMPTYSTR);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy4, gbc);

/*
        CMSAdminUtil.resetGBC(gbc);
        JLabel dummy = new JLabel(" ");
        JLabel dummy5 = new JLabel(" ");
        gbc.weighty = 0.1;
        CMSAdminUtil.addEntryField(this, dummy, dummy5, gbc);
*/

        super.init();
    }

    @Override
    public void getUpdateInfo(WizardInfo info) {
    }
}
