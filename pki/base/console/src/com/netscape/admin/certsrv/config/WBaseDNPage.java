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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
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
public class WBaseDNPage extends WizardBasePanel implements IWizardPanel {
    protected JTextField mCNText, mOUText, mOText, mLText, mSTText, mCText;
    protected JTextArea mSubjectDNText;
    public static final String CN = "CN=";
    public static final String OU = "OU=";
    public static final String O = "O=";
    public static final String L = "L=";
    public static final String ST = "ST=";
    public static final String C = "C=";
    public static final String cn = "cn=";
    public static final String ou = "ou=";
    public static final String o = "o=";
    public static final String l = "l=";
    public static final String st = "st=";
    public static final String c = "c=";
    protected JRadioButton mDNComponents;
    protected JRadioButton mDNString;
    protected JTextField mSubjectStringText;
    protected JLabel cnLabel;
    protected JLabel ouLabel;
    protected JLabel oLabel;
    protected JLabel lLabel;
    protected JLabel stLabel;
    protected JLabel cLabel;
    protected JLabel subjectDNLabel;
    protected Color mActiveColor;
    //protected JTextArea dnDesc;
    protected boolean displayWarning=false;
    protected String mPanelName;


    public WBaseDNPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        return true;
    }

    public boolean validatePanel() {
        String str = "";
        if (mDNComponents.isSelected()) {
            str = mOText.getText().trim();
        } else {
            String dnString = mSubjectStringText.getText().trim();
            StringTokenizer tokenizer = new StringTokenizer(dnString, ",");
            while (tokenizer.hasMoreTokens()) {
                String element = ((String)tokenizer.nextToken()).trim();
                if (element.startsWith(O) || element.startsWith(o)) {
                    int index = element.indexOf("=");
                    if (index > -1) {
                        str = element.substring(index+1);
                        break;
                    }
                }
            }
        }

        if (str.equals("") && !displayWarning) {
            String errorMsg = 
              mResource.getString(mPanelName+"_DIALOG_MISSINGO_MESSAGE");
            JOptionPane.showMessageDialog(new JFrame(), errorMsg, "Warning",
              JOptionPane.WARNING_MESSAGE,
              CMSAdminUtil.getImage(CMSAdminResources.IMAGE_WARN_ICON));
/*
            WarningDialog dialog = new WarningDialog(new JFrame(),
              "_TEXT_MISSINGO_LABEL");
*/
            displayWarning = true;
            return false;
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void callHelp() {
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    protected void populateDN(String str) {
        StringTokenizer tokenizer = new StringTokenizer(str, ",");
        boolean isDNString = false;
        while (tokenizer.hasMoreTokens()) {
            String element = (String)tokenizer.nextToken();
            element = element.trim();
            int index = element.indexOf('=');
            String val = element.substring(index+1);
            if (element.startsWith(CN) || element.startsWith(cn)) {
                mCNText.setText(val);
            } else if (element.startsWith(OU) || element.startsWith(ou)) {
                mOUText.setText(val);
            } else if (element.startsWith(O) || element.startsWith(o)) {
                mOText.setText(val);
            } else if (element.startsWith(L) || element.startsWith(l)) {
                mLText.setText(val);
            } else if (element.startsWith(ST) || element.startsWith(st)) {
                mSTText.setText(val);
            } else if (element.startsWith(C) || element.startsWith(c)) {
                mCText.setText(val);
            } else {
                isDNString = true;
            }
        }

        mSubjectStringText.setText(str);

        if (isDNString) {
            mDNString.setSelected(true);
            enableFields(false, getBackground());
        } else {
            mDNComponents.setSelected(true);
            enableFields(true, mActiveColor);
        }
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

/*
        JLabel currentDN = makeJLabel("SUBJECTNAME");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(currentDN, gbc);

        dnDesc = createTextArea(" ", 2, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(dnDesc, gbc);
*/
        
/*
        JTextArea desc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CACERT2WIZARD_TEXT_DN_LABEL"), 80), 1, 80);
*/

        JTextArea desc = createTextArea(mResource.getString(
          mPanelName+"_LABEL_DN_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        mDNComponents = makeJRadioButton("DNCOMP", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mDNComponents, gbc);
     
        cnLabel = makeJLabel("CN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(cnLabel, gbc);

        mCNText = new JTextField(30); 
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCNText, gbc);

/*
        JTextArea dummy = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, cnLabel, mCNText, dummy, gbc);
*/
        //CMSAdminUtil.addComponents(this, cnLabel, mCNText, gbc);

        ouLabel = makeJLabel("OU");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE,4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(ouLabel, gbc);

        mOUText = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mOUText, gbc);

/*
        JTextArea dummy1 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, ouLabel, mOUText, dummy1, gbc);
*/
//        CMSAdminUtil.addComponents(this, ouLabel, mOUText, gbc);

        oLabel = makeJLabel("O");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(oLabel, gbc);

        mOText = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mOText, gbc);

/*
        JTextArea dummy2 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, oLabel, mOText, dummy2, gbc);
*/
        //CMSAdminUtil.addComponents(this, oLabel, mOText, gbc);

        lLabel = makeJLabel("LOCALITY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(lLabel, gbc);

        mLText = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mLText, gbc);
/*
        JTextArea dummy3 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, lLabel, mLText, dummy3, gbc);
*/
        //CMSAdminUtil.addComponents(this, lLabel, mLText, gbc);

        stLabel = makeJLabel("STATE");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(stLabel, gbc);

        mSTText = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSTText, gbc);
/*
        JTextArea dummy4 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, stLabel, mSTText, dummy4, gbc);
*/
        //CMSAdminUtil.addComponents(this, stLabel, mSTText, gbc);

        cLabel = makeJLabel("COUNTRY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(cLabel, gbc);

        mCText = new JTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCText, gbc);
/*
        JTextArea dummy5 = createTextArea(" ", 1, 1);
        CMSAdminUtil.addComponents(this, cLabel, mCText, dummy5, gbc);
*/
        //CMSAdminUtil.addComponents(this, cLabel, mCText, gbc);

        subjectDNLabel = makeJLabel("SELECTEDDN");
        mSubjectDNText = new SubjectDNTextArea(3, 30);
        mSubjectDNText.setLineWrap(true);
        mSubjectDNText.setBackground(getBackground());
        mSubjectDNText.setEditable(false);
        mSubjectDNText.setCaretColor(getBackground());
        CMSAdminUtil.resetGBC(gbc);
        //gbc.weighty = 1.0;
        CMSAdminUtil.addComponents(this, subjectDNLabel, mSubjectDNText, gbc);

        mDNString = makeJRadioButton("DNSTRING", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mDNString, gbc);

        ButtonGroup group = new ButtonGroup();
        group.add(mDNString);
        group.add(mDNComponents);

        mSubjectStringText = new JTextField(256);
/*
        mSubjectStringText = new JTextArea(null, null, 0, 0);        
        mSubjectStringText.setBorder(BorderFactory.createLineBorder(Color.black));
        JScrollPane scrollPane = new JScrollPane(mSubjectStringText,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(50, 20));
*/
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = gbc.REMAINDER;
        add(mSubjectStringText, gbc);
        //mSubjectStringText.setLineWrap(true);
        mActiveColor = mCNText.getBackground();

        CMSAdminUtil.resetGBC(gbc);
        JLabel d1 = new JLabel();
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.gridwidth = gbc.REMAINDER;
        add(d1, gbc);
        

        mCNText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mOUText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mOText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mLText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mSTText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);
        mCText.getDocument().addDocumentListener((DocumentListener)mSubjectDNText);

        super.init();
    }

    protected void enableFields(boolean enable, Color color) {
        CMSAdminUtil.enableJTextField(mCNText, enable, color);
        CMSAdminUtil.enableJTextField(mOUText, enable, color);
        CMSAdminUtil.enableJTextField(mOText, enable, color);
        CMSAdminUtil.enableJTextField(mLText, enable, color);
        CMSAdminUtil.enableJTextField(mSTText, enable, color);
        CMSAdminUtil.enableJTextField(mCText, enable, color);
        cnLabel.setEnabled(enable);
        ouLabel.setEnabled(enable);
        oLabel.setEnabled(enable);
        lLabel.setEnabled(enable);
        stLabel.setEnabled(enable);
        cLabel.setEnabled(enable);
        subjectDNLabel.setEnabled(enable);
        CMSAdminUtil.repaintComp(cnLabel);
        CMSAdminUtil.repaintComp(ouLabel);
        CMSAdminUtil.repaintComp(oLabel);
        CMSAdminUtil.repaintComp(lLabel);
        CMSAdminUtil.repaintComp(stLabel);
        CMSAdminUtil.repaintComp(cLabel);
        CMSAdminUtil.repaintComp(subjectDNLabel);
        if (enable)
            CMSAdminUtil.enableJTextField(mSubjectStringText, !enable, 
              getBackground());
        else
            CMSAdminUtil.enableJTextField(mSubjectStringText, !enable, 
              mActiveColor);
    }

    public void actionPerformed(ActionEvent e) {
        if (mDNComponents.isSelected()) {
            enableFields(true, mActiveColor);
        } else {
            enableFields(false, getBackground());
        } 
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
