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
package com.netscape.admin.certsrv.config;

import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * CA signing cert for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
public class WBaseDNValidityPage extends WizardBasePanel {
    public JTextField mCNText, mOUText, mOText, mLText, mSTText, mCText;
    public JTextField mValidityText;
    public JComboBox mUnitBox;
    public JLabel validityLbl;
    public JTextArea mSubjectDNText, desc1;
    public static final String CN = "CN=";
    public static final String OU = "OU=";
    public static final String O = "O=";
    public static final String L = "L=";
    public static final String ST = "ST=";
    public static final String C = "C=";

    public WBaseDNValidityPage(String panelName) {
        super(panelName);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea desc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERT2WIZARD_TEXT_DN_LABEL"), 80), 1, 80);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);
     
        JLabel cnLabel = makeJLabel("CN");
        mCNText = new JTextField(30); 
/*
        JTextArea dummy = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, cnLabel, mCNText, dummy, gbc);
*/
        CMSAdminUtil.addComponents(this, cnLabel, mCNText, gbc);

        JLabel ouLabel = makeJLabel("OU");
        mOUText = new JTextField(30);
/*
        JTextArea dummy1 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, ouLabel, mOUText, dummy1, gbc);
*/
        CMSAdminUtil.addComponents(this, ouLabel, mOUText, gbc);

        JLabel oLabel = makeJLabel("O");
        mOText = new JTextField(30);
/*
        JTextArea dummy2 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, oLabel, mOText, dummy2, gbc);
*/
        CMSAdminUtil.addComponents(this, oLabel, mOText, gbc);

        JLabel lLabel = makeJLabel("LOCALITY");
        mLText = new JTextField(30);
/*
        JTextArea dummy3 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, lLabel, mLText, dummy3, gbc);
*/
        CMSAdminUtil.addComponents(this, lLabel, mLText, gbc);

        JLabel stLabel = makeJLabel("STATE");
        mSTText = new JTextField(30);
/*
        JTextArea dummy4 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, stLabel, mSTText, dummy4, gbc);
*/
        CMSAdminUtil.addComponents(this, stLabel, mSTText, gbc);

        JLabel cLabel = makeJLabel("COUNTRY");
        mCText = new JTextField(30);
/*
        JTextArea dummy5 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, cLabel, mCText, dummy5, gbc);
*/
        CMSAdminUtil.addComponents(this, cLabel, mCText, gbc);

        JLabel subjectDNLabel = makeJLabel("SELECTEDDN");
        mSubjectDNText = new SubjectDNTextArea(3, 30);
        mSubjectDNText.setLineWrap(true);
        mSubjectDNText.setBackground(getBackground());
        mSubjectDNText.setEditable(false);
        mSubjectDNText.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        //gbc.weighty = 1.0;
        CMSAdminUtil.addComponents(this, subjectDNLabel, mSubjectDNText, gbc);

        desc1 = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERT2WIZARD_TEXT_VALIDITY_LABEL"), 80), 1, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc1, gbc);
        
        validityLbl = makeJLabel("VALIDITY");
        mValidityText = new JTextField(5);
        mUnitBox = makeJComboBox("VALIDITY");
        gbc.weighty = 1.0;
        CMSAdminUtil.addComponents(this, validityLbl, mValidityText, mUnitBox,
          gbc);

        mCNText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mOUText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mOText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mLText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mSTText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mCText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);

        super.init();
    }

    public class SubjectDNTextArea extends JTextArea implements 
      DocumentListener {

        public SubjectDNTextArea(int rows, int columns) {
            super(rows, columns);
        }

        public void insertUpdate(DocumentEvent e) {
            super.setText(updateStr());
        }

        public void removeUpdate(DocumentEvent e) {
            super.setText(updateStr());
        }
 
        public void changedUpdate(DocumentEvent e) {
            super.setText(updateStr());
        }

        private String updateStr() {
            String cnStr = mCNText.getText().trim();
            String ouStr = mOUText.getText().trim();
            String oStr = mOText.getText().trim();
            String lStr = mLText.getText().trim();
            String stStr = mSTText.getText().trim();
            String cStr = mCText.getText().trim();

            String result = "";
            result = result+appendStr(result, CN, cnStr);
            result = result+appendStr(result, OU, ouStr);
            result = result+appendStr(result, O, oStr);
            result = result+appendStr(result, L, lStr);
            result = result+appendStr(result, ST, stStr);
            result = result+appendStr(result, C, cStr);

            return result;
        }

        private String appendStr(String origStr, String prefix, String suffix) {
            String result = "";
            if (suffix.equals(""))
                return result;

            result = prefix + suffix;
            if (!origStr.equals("")) {
                result = ", "+result;
            }
            return result;
        }
    }
}
