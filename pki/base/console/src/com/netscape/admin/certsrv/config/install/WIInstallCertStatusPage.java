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
import java.awt.event.*;
import java.util.*;
import java.io.*;
import javax.swing.*;
import javax.swing.text.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Status page of certificate installation.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIInstallCertStatusPage extends WizardBasePanel implements IWizardPanel {
    private Color mActiveColor;
    private JTextArea desc;
    private JRadioButton mFileBtn;
    private JRadioButton mBase64Btn;
    private String mPanelName;
    protected JTextArea mBase64Text;
    private JTextField mFileText;
    protected JButton mPaste;
    protected String mHelpIndex;
    protected String mCertChain;
    protected String mCertFilePath;
    
    WIInstallCertStatusPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String str = mResource.getString(mPanelName+"_TEXT_DESC_LABEL");
        desc.setText(str);
        return true; 
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean validatePanel() {
        if (mFileBtn.isSelected()) {
            mCertFilePath = mFileText.getText().trim();
            if (mCertFilePath.equals("")) {
                setErrorMessage("EMPTYFILEFIELD");
                return false;
            }
        } else if (mBase64Btn.isSelected()) {
            mCertChain = mBase64Text.getText().trim();
            if (mCertChain.equals("")) {
                setErrorMessage("B64EEMPTY");
                return false;
            }
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_IMPORT_CERT_CHAIN;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
        if (mFileBtn.isSelected()) {
            rawData = rawData+"&"+Constants.PR_CERT_FILEPATH+"="+mCertFilePath;
        } else if (mBase64Btn.isSelected()) {
            rawData = rawData+"&"+ConfigConstants.PR_CERT_CHAIN+"="+mCertChain;
        }

        rawData = rawData+"&"+Constants.PR_CERTIFICATE_TYPE+"="+wizardInfo.getCertType();

        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();
        if (!ready) {
            String str = getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  mPanelName+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else if (str.equals("incompleteCertChain")) {
                String errormsg = mResource.getString(mPanelName+"_INCOMPLETECERTCHAIN");
                int status = JOptionPane.showConfirmDialog(mAdminFrame, errormsg, "Information",
                  JOptionPane.OK_CANCEL_OPTION, JOptionPane.INFORMATION_MESSAGE,
                  CMSAdminUtil.getImage(CMSAdminResources.IMAGE_INFO_ICON));
                if (status == JOptionPane.OK_OPTION) {
                    rawData = rawData+"&"+ConfigConstants.NOT_IMPORT_CHAIN+"="+
                      ConfigConstants.TRUE;
                    ready = send(rawData, wizardInfo);
                    return true;
                } else {
                    setErrorMessage(mResource.getString(mPanelName+"_ERROR1"));
                    return false; 
                }
            } else 
                setErrorMessage(str);
        }
        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        desc = createTextArea("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mFileBtn = makeJRadioButton("FILE", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mFileBtn, gbc);

        mFileText = makeJTextField(50);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, COMPONENT_SPACE, 0);
        add(mFileText, gbc);
        mActiveColor = mFileText.getBackground();

        mBase64Btn = makeJRadioButton("BASE64", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mBase64Btn, gbc);

        ButtonGroup btngroup = new ButtonGroup();
        btngroup.add(mFileBtn);
        btngroup.add(mBase64Btn);

        JTextArea desc1 = createTextArea(mResource.getString(
          mPanelName+"_TEXT_DESC1_LABEL"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,4*COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc1, gbc);

        mBase64Text = new JTextArea(null, null, 0, 0);
        JScrollPane scrollPane = new JScrollPane(mBase64Text,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(50, 20));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = gbc.REMAINDER;
        add(scrollPane, gbc);

        mPaste = makeJButton("PASTE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mPaste, gbc);

        JLabel dummy = new JLabel(" ");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.anchor = gbc.NORTHWEST;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        add(dummy, gbc);

        enableFields(mFileText, true, mActiveColor);
        enableFields(mBase64Text, false, getBackground());

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mPaste)) {
            mBase64Text.paste();
        } else if (e.getSource().equals(mFileBtn)) {
            enableFields(mFileText, true, mActiveColor);
            enableFields(mBase64Text, false, getBackground());
        } else if (e.getSource().equals(mBase64Btn)) {
            enableFields(mFileText, false, getBackground());
            enableFields(mBase64Text, true, mActiveColor);
        }
    }

    private void enableFields(JTextComponent comp1, boolean enable, Color color) {
        comp1.setEnabled(enable);
        comp1.setEditable(enable);
        comp1.setBackground(color);
        CMSAdminUtil.repaintComp(comp1);
    }
}
