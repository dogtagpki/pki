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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.io.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import javax.swing.text.*;

/**
 * Setup key information for certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WKeyPage extends WizardBasePanel implements IWizardPanel, ItemListener {
    private Color mActiveColor;
    private JPanel mNicknamePanel;
    private JRadioButton mExistingKeyBtn;
    private JRadioButton mNewKeyBtn;
    private JComboBox mKeyTypeBox, mDSAKeyTypeBox;
    private JComboBox mKeyLengthBox, mDSAKeyLengthBox;
    private JComboBox mTokenBox, mNicknameBox;
    private JTextField mKeyLengthText;
    private JLabel keyHeading, keyTypeLbl, keyLengthLbl, unitLbl,
      keyLengthCustomLbl, unit1Lbl, mTokenLbl, mNicknameLbl;
    private JLabel keyLengthCustomText;
    private static final String PANELNAME = "KEYWIZARD";
    private CertSetupWizardInfo wizardInfo;
    private static final String HELPINDEX =
      "configuration-keycert-wizard-key-help";
    
    WKeyPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WKeyPage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE))
            return false;

        String title = "";
        String certType = wizardInfo.getCertType();
        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) 
            title = mResource.getString("KEYWIZARD_BORDER_CASIGNING_LABEL");
        else if (certType.equals(Constants.PR_RA_SIGNING_CERT))
            title = mResource.getString("KEYWIZARD_BORDER_RASIGNING_LABEL");
        else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT))
            title = mResource.getString("KEYWIZARD_BORDER_KRATRANSPORT_LABEL");
        else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT))
            title = mResource.getString("KEYWIZARD_BORDER_OCSPSIGNING_LABEL");
        else if (certType.equals(Constants.PR_SERVER_CERT) ||
          certType.equals(Constants.PR_SERVER_CERT_RADM))
            title = mResource.getString("KEYWIZARD_BORDER_SERVER_LABEL");
        else if (certType.equals(Constants.PR_OTHER_CERT))
            title = mResource.getString("KEYWIZARD_BORDER_OTHER_LABEL");
          
        setBorder(new TitledBorder(title));
        if (certType.equals(Constants.PR_OTHER_CERT)) {
            mNicknamePanel.setVisible(true);
            mNicknameLbl.setVisible(true);
            mNicknameBox.setVisible(true);
            if (mNicknameBox.getItemCount() <= 0) {
                String str = wizardInfo.getNicknames();
                StringTokenizer tokenizer1 = new StringTokenizer(str, ",");
                while (tokenizer1.hasMoreTokens()) { 
                    mNicknameBox.addItem((String)tokenizer1.nextToken());
                }
            }
        } else {
            mNicknamePanel.setVisible(false);
            mNicknameLbl.setVisible(false);
            mNicknameBox.setVisible(false);
        }

        if (mTokenBox.getItemCount() > 0) {
/*
            if (mNewKeyBtn.isSelected() || certType.equals(Constants.PR_OTHER_CERT)) {
                mTokenBox.setEnabled(true);
                mTokenLbl.setEnabled(true);
            } else {
                mTokenBox.setEnabled(false);
                mTokenLbl.setEnabled(false);
            }
*/
            return true;
		}

        String tokenList = wizardInfo.getTokenList();
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ",");
        while (tokenizer.hasMoreTokens()) {
            mTokenBox.addItem((String)tokenizer.nextToken());
        }

        mTokenBox.addItemListener(this);

        if (certType.equals(Constants.PR_CA_SIGNING_CERT) ||
          certType.equals(Constants.PR_RA_SIGNING_CERT) ||
          certType.equals(Constants.PR_OCSP_SIGNING_CERT) ) {
            mDSAKeyTypeBox.setVisible(true);
            mKeyTypeBox.setVisible(false);
        } else {
            mDSAKeyTypeBox.setVisible(false);
            mKeyTypeBox.setVisible(true);
        }

        String type = "RSA";
        if (mDSAKeyTypeBox.isVisible()) {
            type = (String)mDSAKeyTypeBox.getSelectedItem();
        }

        if (type.equals("RSA")) {
            mDSAKeyLengthBox.setVisible(false);
            mKeyLengthBox.setVisible(true);
        } else {
            mKeyLengthBox.setVisible(false);
            mDSAKeyLengthBox.setVisible(true);
        }

        enableKeyLengthFields();

        //if (mNewKeyBtn.isSelected() || certType.equals(Constants.PR_OTHER_CERT)) {
        if (mNewKeyBtn.isSelected()) {
            mTokenBox.setEnabled(true);
            mTokenLbl.setEnabled(true);
        } else {
            mTokenBox.setEnabled(false);
            mTokenLbl.setEnabled(false);
        }

/*
        if (certType.equals(Constants.PR_SERVER_CERT)) {
            mKeyLengthBox.removeItem("4096");
            mKeyLengthBox.setSelectedIndex(0);
        }
*/

        if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
            mKeyLengthBox.removeItem("768");
            mKeyLengthBox.removeItem("4096");
            mKeyLengthBox.removeItem("Custom");
            mKeyLengthBox.setSelectedIndex(0);
        }

        CMSAdminUtil.repaintComp(mTokenBox);
        CMSAdminUtil.repaintComp(mTokenLbl);
        CMSAdminUtil.repaintComp(mNicknamePanel);
        CMSAdminUtil.repaintComp(mNicknameLbl);
        CMSAdminUtil.repaintComp(mNicknameBox);

        return true; 
    }

    public boolean validatePanel() {
        if (mKeyLengthText.isEnabled()) {
            String str = mKeyLengthText.getText().trim();
            if (str.equals("")) {
                setErrorMessage("BLANKLEN");
                return false;
            } else {
                try {
                    int num = Integer.parseInt(str);
                    if (num <= 0) {
                        setErrorMessage("INVALIDKEYLEN");
                        return false;
                    }
                } catch (NumberFormatException e) {
                    setErrorMessage("NONINTEGER");
                    return false;
                }
            }
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();

        if (mNewKeyBtn.isSelected()) {
            String val = "";

            if (mKeyLengthBox.isVisible()) {
                val = (String)mKeyLengthBox.getSelectedItem();
            } else {
				if (mDSAKeyLengthBox.isVisible())
                	val = (String)mDSAKeyLengthBox.getSelectedItem();
			}

            if (val.equals("Custom")) {
                wizardInfo.addEntry(Constants.PR_KEY_LENGTH, 
                  mKeyLengthText.getText().trim());
                nvps.add(Constants.PR_KEY_LENGTH, mKeyLengthText.getText().trim());
            } else {
                wizardInfo.addEntry(Constants.PR_KEY_LENGTH, val.trim());
                nvps.add(Constants.PR_KEY_LENGTH, val.trim());
            }
     
            if (mKeyTypeBox.isVisible()) {
                wizardInfo.addEntry(Constants.PR_KEY_TYPE,
                  (String)mKeyTypeBox.getSelectedItem());
                nvps.add(Constants.PR_KEY_TYPE, (String)mKeyTypeBox.getSelectedItem());
            } else if (mDSAKeyTypeBox.isVisible()) {
                wizardInfo.addEntry(Constants.PR_KEY_TYPE,
                  (String)mDSAKeyTypeBox.getSelectedItem());
                nvps.add(Constants.PR_KEY_TYPE, (String)mDSAKeyTypeBox.getSelectedItem());
            }
        }

        startProgressStatus();

        String certType = wizardInfo.getCertType();
        nvps.add(Constants.PR_SUBJECT_NAME, "");
        nvps.add(Constants.PR_CERTIFICATE_TYPE, certType);

        try {
            // validate the key length
            connection.validate(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_KEY_LENGTH, nvps);

            NameValuePairs response = null;
            if (!mNewKeyBtn.isSelected()) {

                if (mNicknameBox.isVisible()) {
                    String nicknameStr = (String)mNicknameBox.getSelectedItem();
                    nvps.add(Constants.PR_NICKNAME, nicknameStr);
                    response = connection.process(
                      DestDef.DEST_SERVER_ADMIN,
                      ScopeDef.SC_SUBJECT_NAME, 
                      wizardInfo.getCertType(), nvps);
                    wizardInfo.addEntry(Constants.PR_NICKNAME, nicknameStr);
                } else {
                    response = connection.read(
                      DestDef.DEST_SERVER_ADMIN,
                      ScopeDef.SC_SUBJECT_NAME, 
                      wizardInfo.getCertType(), nvps);
                }

                NameValuePair nvp = response.getPair(Constants.PR_SUBJECT_NAME);

                wizardInfo.addEntry(Constants.PR_SUBJECT_NAME, nvp.getValue());
            }

            if (mNewKeyBtn.isSelected()) {
                String tokenName = (String)mTokenBox.getSelectedItem();
                if (tokenName.equals("internal")) 
                    tokenName = Constants.PR_INTERNAL_TOKEN_NAME;
                nvps.removeAllPairs();
                nvps.add(Constants.PR_TOKEN_NAME, tokenName);
                response = connection.process(DestDef.DEST_SERVER_ADMIN,
                  ScopeDef.SC_TOKEN_STATUS, Constants.RS_ID_CONFIG, nvps);
                
                NameValuePair result = response.getPair(Constants.PR_LOGGED_IN);
                wizardInfo.addEntry(Constants.PR_LOGGED_IN, result.getValue()); 
                wizardInfo.addEntry(Constants.PR_TOKEN_NAME, tokenName);
            }
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
            endProgressStatus();
            return false;
        }

        endProgressStatus();
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JPanel panel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel, gbc);
        
        JTextArea selectTokenLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_SELECTTOKEN_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,0);
        panel.add(selectTokenLbl, gbc);
 
        mTokenLbl = makeJLabel("TOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.insets = new Insets(COMPONENT_SPACE, 0,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        panel.add(mTokenLbl, gbc);

        mTokenBox = new JComboBox();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.weightx = 1.0;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel.add(mTokenBox, gbc);

        JTextArea dummy2 = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        panel.add(dummy2, gbc);

        JTextArea createKeyLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_KEYPAIR_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(createKeyLbl, gbc);

        mExistingKeyBtn = makeJRadioButton("OLDKEY", true);  
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mExistingKeyBtn, gbc);

        mNicknamePanel = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        mNicknamePanel.setLayout(gb3);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);        
        gbc.fill = gbc.BOTH;
        gbc.weightx = 1.0;
        add(mNicknamePanel, gbc);

        mNicknameLbl = makeJLabel("NICKNAME");
        CMSAdminUtil.resetGBC(gbc);
        //gbc.anchor = gbc.CENTER;
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        //gbc.fill = gbc.NONE;
        gbc.fill = gbc.HORIZONTAL;
        mNicknamePanel.add(mNicknameLbl, gbc);

        JLabel dummy18 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.fill = gbc.HORIZONTAL;
        mNicknamePanel.add(dummy18, gbc);

        mNicknameBox = new JComboBox();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.fill = gbc.BOTH;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, 2*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        mNicknamePanel.add(mNicknameBox, gbc);

/*
        JTextArea dummy22 = createTextArea(" ", 1, 5);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        mNicknamePanel.add(dummy22, gbc);
*/

        mNewKeyBtn = makeJRadioButton("NEWKEY", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mNewKeyBtn, gbc);

        ButtonGroup grp = new ButtonGroup();
        grp.add(mExistingKeyBtn);
        grp.add(mNewKeyBtn);

/*
        JPanel panel = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel.setLayout(gb1);
*/

        keyHeading = makeJLabel("KEY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(keyHeading, gbc);

        keyTypeLbl = makeJLabel("KEYTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(keyTypeLbl, gbc);

        mKeyTypeBox = makeJComboBox("KEYTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mKeyTypeBox, gbc);

        mDSAKeyTypeBox = makeJComboBox("DSAKEYTYPE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.fill = gbc.NONE;
        add(mDSAKeyTypeBox, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(dummy, gbc);

        keyLengthLbl = makeJLabel("KEYLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.fill = gbc.NONE;
        //gbc.weighty = 1.0;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(keyLengthLbl, gbc);
        //panel.add(keyLengthLbl, gbc);

        mKeyLengthBox = makeJComboBox("KEYLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        //gbc.weighty = 1.0;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mKeyLengthBox, gbc);
        //panel.add(mKeyLengthBox, gbc);

        mDSAKeyLengthBox = makeJComboBox("DSAKEYLENGTH");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        //gbc.weighty = 1.0;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mDSAKeyLengthBox, gbc);
        //panel.add(mDSAKeyLengthBox, gbc);

        unitLbl = makeJLabel("UNITS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.CENTER;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(0, 0,COMPONENT_SPACE, COMPONENT_SPACE);
        add(unitLbl, gbc);
        //panel.add(unitLbl, gbc);

        JPanel panel1 = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        panel1.setLayout(gb2);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, 0, 0, 0);
        add(panel1, gbc);

        keyLengthCustomText = makeJLabel("CUSTOMKEY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        panel1.add(keyLengthCustomText, gbc);

        mKeyLengthText = makeJTextField(7);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        panel1.add(mKeyLengthText, gbc);
        mActiveColor = mKeyLengthText.getBackground();

        unit1Lbl = makeJLabel("UNITS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        panel1.add(unit1Lbl, gbc);

        JLabel dummy1 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy1, gbc);

        enableFields(false, getBackground());
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        if (mNewKeyBtn.isSelected()) {
            wizardInfo.addEntry(wizardInfo.KEY_MATERIAL, Constants.TRUE);
        } else if (mExistingKeyBtn.isSelected())
            wizardInfo.addEntry(wizardInfo.KEY_MATERIAL, Constants.FALSE);
    }

    public void actionPerformed(ActionEvent e) {
        Object source = e.getSource();
        if (source.equals(mExistingKeyBtn)) {
            enableFields(false, getBackground());
            enableKeyLengthFields();
            mTokenBox.setEnabled(false);
            mTokenLbl.setEnabled(false);
        } else if (source.equals(mNewKeyBtn)) {
            String certType = wizardInfo.getCertType();
            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                WarningDialog dialog = new WarningDialog(wizardInfo.getFrame(),
                  "_TEXT_DESC_LABEL");
            }
            enableFields(true, mActiveColor);
            enableKeyLengthFields();
            mTokenBox.setEnabled(true);
            mTokenLbl.setEnabled(true);
        }
        CMSAdminUtil.repaintComp(mTokenBox);
        CMSAdminUtil.repaintComp(mTokenLbl);
    }

    public void itemStateChanged(ItemEvent e) {
        if (e.getSource().equals(mKeyLengthBox) || 
          e.getSource().equals(mDSAKeyLengthBox)) {
            enableKeyLengthFields();
        } else if (e.getSource().equals(mKeyTypeBox) || 
          e.getSource().equals(mDSAKeyTypeBox)) {
            String type = "";
            if (mKeyTypeBox.isVisible())
                type = (String)mKeyTypeBox.getSelectedItem();
            else if (mDSAKeyTypeBox.isVisible())
                type = (String)mDSAKeyTypeBox.getSelectedItem();
         
            if (type.equals("RSA")) {
                mDSAKeyLengthBox.setVisible(false);
                mKeyLengthBox.setVisible(true);
            } else {
                mDSAKeyLengthBox.setVisible(true);
                mKeyLengthBox.setVisible(false);
            }
            enableKeyLengthFields();
            CMSAdminUtil.repaintComp(this);
        }
    }

    private void enableKeyLengthFields() {
        String value = "";
        
        if (mKeyLengthBox.isVisible())
            value = (String)mKeyLengthBox.getSelectedItem();
        else
            value = (String)mDSAKeyLengthBox.getSelectedItem();

        if (value.equals("Custom") && mNewKeyBtn.isSelected()) {
            enableFields(keyLengthCustomText, mKeyLengthText, true, mActiveColor);
            enableFields(unit1Lbl, null, true, mActiveColor);
        } else {
            enableFields(keyLengthCustomText, mKeyLengthText, false,
              getBackground());
            enableFields(unit1Lbl, null, false, getBackground());
        }
    }

    protected void enableFields(JComponent comp1, JTextComponent comp2, 
      boolean enable, Color color) {
        if (comp1 != null) {
            comp1.setEnabled(enable);
            CMSAdminUtil.repaintComp(comp1);
        }
        if (comp2 != null) {
            comp2.setEnabled(enable);
            comp2.setBackground(color);
            comp2.setEditable(enable);
            CMSAdminUtil.repaintComp(comp2);
        }
    }

    private void enableFields(boolean enable, Color color) {
        keyHeading.setEnabled(enable);
        keyTypeLbl.setEnabled(enable);
        keyLengthLbl.setEnabled(enable);
        unitLbl.setEnabled(enable);
        unit1Lbl.setEnabled(enable);
        keyLengthCustomText.setEnabled(enable);
        mKeyLengthText.setEnabled(enable);
        mKeyLengthText.setEditable(enable);
        mKeyLengthText.setBackground(color);
        mKeyTypeBox.setEnabled(enable);
        mDSAKeyTypeBox.setEnabled(enable);
        mKeyLengthBox.setEnabled(enable);
        mDSAKeyLengthBox.setEnabled(enable);
        repaintComp(keyHeading);
        repaintComp(keyTypeLbl);
        repaintComp(keyLengthLbl);
        repaintComp(unitLbl);
        repaintComp(unit1Lbl);
        repaintComp(keyLengthCustomText);
        repaintComp(mKeyLengthText);
        repaintComp(mKeyTypeBox);
        repaintComp(mDSAKeyTypeBox);
        repaintComp(mKeyLengthBox);
        repaintComp(mDSAKeyLengthBox);
    }

    private void repaintComp(JComponent component) {
        component.invalidate();
        component.validate();
        component.repaint(1);
    }
}
