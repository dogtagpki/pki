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
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;

/**
 * Select certificate type from certificate setup wizard.
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.keycert
 */
class WCertTypePage extends WizardBasePanel implements IWizardPanel,
  ItemListener {
    private String mCASigningCert;
    private String mRASigningCert;
    private String mOCSPSigningCert;
    private String mServerCert, mServerCertRadm, mOtherCert;
    private String mKRATransportCert;
    private JTextArea mCALbl;
    private JRadioButton mCABtn;
    private JRadioButton mSubBtn;
    private JComboBox mCertBox;
    private JTextArea mCertType;
    private JTextField mCertTypeText;
    private Color mActiveColor;
    private static final String PANELNAME = "CERTTYPEWIZARD";
    private static final String HELPINDEX =
      "configuration-keycert-wizard-certtype-help";
    
    WCertTypePage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WCertTypePage(JDialog parent, JFrame frame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = frame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        if (wizardInfo.getOperationType().equals(wizardInfo.INSTALLTYPE))
            return false;

        setBorder(makeTitledBorder(PANELNAME));
        if (wizardInfo.getCertType() != null) {
            return true;
        }

        AdminConnection connection = wizardInfo.getAdminConnection();
        NameValuePairs nvps = new NameValuePairs();

        try {
            NameValuePairs response = connection.search(DestDef.DEST_SERVER_ADMIN,
              ScopeDef.SC_SUBSYSTEM, nvps);

            for (int i=0; i<response.size(); i++) {
                NameValuePair nvp = response.elementAt(i);
                String type = nvp.getValue();

                if (type.equals(Constants.PR_RA_INSTANCE)) 
                    mRASigningCert = mResource.getString(
                      "CERTTYPEWIZARD_LABEL_RASIGNINGCERT_LABEL");
                else if (type.equals(Constants.PR_CA_INSTANCE)) 
                    mCASigningCert = mResource.getString(
                      "CERTTYPEWIZARD_LABEL_CASIGNINGCERT_LABEL");
                else if (type.equals(Constants.PR_KRA_INSTANCE))
                    mKRATransportCert = mResource.getString(
                      "CERTTYPEWIZARD_LABEL_KRATRANSPORTCERT_LABEL");
            }
        } catch (EAdminException e) {
            //showErrorDialog(e.toString());
            setErrorMessage(e.toString());
        }

        mOCSPSigningCert = mResource.getString(
          "CERTTYPEWIZARD_LABEL_OCSPSIGNINGCERT_LABEL");

        mServerCert = mResource.getString(
          "CERTTYPEWIZARD_LABEL_SERVERCERT_LABEL");

        mServerCertRadm = mResource.getString(
          "CERTTYPEWIZARD_LABEL_SERVERCERTRADM_LABEL");

        mOtherCert = mResource.getString(
          "CERTTYPEWIZARD_LABEL_OTHER_LABEL");

        mCertBox.removeAllItems();

        if (mCASigningCert != null)
            mCertBox.addItem(mCASigningCert);

        if (mRASigningCert != null)
            mCertBox.addItem(mRASigningCert);

        if (mKRATransportCert != null)
            mCertBox.addItem(mKRATransportCert);

        if (mOCSPSigningCert != null)
            mCertBox.addItem(mOCSPSigningCert);

        if (mServerCert != null)
            mCertBox.addItem(mServerCert);

/*
        if (mServerCertRadm != null)
            mCertBox.addItem(mServerCertRadm);
*/

        mCertBox.addItem(mOtherCert);
        mCertBox.setSelectedIndex(0);

        String certType = (String)mCertBox.getSelectedItem();

            if (certType.equals(mOtherCert)) {
                mCABtn.setEnabled(false);
                mSubBtn.setEnabled(false);
                mCALbl.setEnabled(false);
                mCertType.setEnabled(true);
                mCertTypeText.setEnabled(true);
                mCertTypeText.setBackground(mActiveColor);
            } else {
                mCABtn.setEnabled(true);
                mSubBtn.setEnabled(true);
                mCALbl.setEnabled(true);
                mCertType.setEnabled(false);
                mCertTypeText.setEnabled(false);
                mCertTypeText.setBackground(getBackground());
                if ((mCASigningCert != null) && (certType.equals(mCASigningCert)))
                    enableFields(true,"casigning");
                else if ((mCASigningCert != null) && (mOCSPSigningCert != null)
                     && (certType.equals(mOCSPSigningCert)))
                    enableFields(true,"ocspsigning");
                else if ((mCASigningCert != null) && (mServerCert != null)
                     && (certType.equals(mServerCert)))
                    enableFields(true,"server");
                else if ((mCASigningCert != null) && (mServerCertRadm != null)
                     && (certType.equals(mServerCertRadm)))
                    enableFields(true,"server");
                else
                    enableFields(false,"other");
            }

        CMSAdminUtil.repaintComp(mCABtn);
        CMSAdminUtil.repaintComp(mSubBtn);
        CMSAdminUtil.repaintComp(mCALbl);
        CMSAdminUtil.repaintComp(mCertType);
        CMSAdminUtil.repaintComp(mCertTypeText);
        return true; 
    }

    public boolean validatePanel() {
        String str = (String)mCertBox.getSelectedItem();
        if (str.equals(mOtherCert)) {
            if (mCertTypeText.getText().equals("")) {
                setErrorMessage("BLANKCERTTYPE");
                return false;
            }
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        NameValuePairs nvps = new NameValuePairs();
        AdminConnection connection = wizardInfo.getAdminConnection();
        startProgressStatus();
        String item = ((String)mCertBox.getSelectedItem()).trim();

        if (mCASigningCert != null && item.equals(mCASigningCert.trim()))
            wizardInfo.put(Constants.PR_CERTIFICATE_TYPE,
              Constants.PR_CA_SIGNING_CERT);
        else if (mRASigningCert != null && item.equals(mRASigningCert.trim()))
            wizardInfo.put(Constants.PR_CERTIFICATE_TYPE,
              Constants.PR_RA_SIGNING_CERT);
        else if (mKRATransportCert != null && 
          item.equals(mKRATransportCert.trim()))
            wizardInfo.put(Constants.PR_CERTIFICATE_TYPE,
              Constants.PR_KRA_TRANSPORT_CERT);
        else if (mServerCert != null && item.equals(mServerCert.trim()))
            wizardInfo.put(Constants.PR_CERTIFICATE_TYPE, 
              Constants.PR_SERVER_CERT);
        else if (mServerCertRadm != null && item.equals(mServerCertRadm.trim()))
            wizardInfo.put(Constants.PR_CERTIFICATE_TYPE, 
              Constants.PR_SERVER_CERT_RADM);
        else if (mOCSPSigningCert != null && item.equals(mOCSPSigningCert.trim()))
            wizardInfo.put(Constants.PR_CERTIFICATE_TYPE, 
              Constants.PR_OCSP_SIGNING_CERT);
        else if (mOtherCert != null && item.equals(mOtherCert.trim())) 
            wizardInfo.put(Constants.PR_CERTIFICATE_TYPE, 
              Constants.PR_OTHER_CERT);
        
        if (item.equals(mOtherCert.trim())) {
            try {
                NameValuePairs response = null;

                response = connection.read(DestDef.DEST_SERVER_ADMIN,
                  ScopeDef.SC_GET_NICKNAMES, wizardInfo.getCertType(), nvps);
                NameValuePair nvp = response.getPair(Constants.PR_ALL_NICKNAMES);
                wizardInfo.setNicknames(nvp.getValue());
            } catch (EAdminException e) {
                setErrorMessage(e.toString());
                endProgressStatus();
                return false;
            }
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

/*
        JTextArea desc = createTextArea(
          CMSAdminUtil.wrapText(mResource.getString(
            "CERTTYPEWIZARD_TEXT_HEADING_LABEL"), 80), 1, 80);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);
*/
        JTextArea heading = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_HEADING_LABEL"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(heading, gbc);

        JTextArea heading1 = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_HEADING1_LABEL"));

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(heading1, gbc);

        mCertBox = new JComboBox();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mCertBox, gbc);
        mCertBox.addItemListener(this);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy, gbc);
       
        mCertType = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_CERTTYPE_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCertType, gbc);
       
/*
        JLabel dummy1 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy1, gbc);
*/

        mCertTypeText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        add(mCertTypeText, gbc);
        mActiveColor = mCertTypeText.getBackground();
  
        JLabel dummy2 = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        add(dummy2, gbc);

        mCALbl = createTextArea(mResource.getString(
          "CERTTYPEWIZARD_TEXT_CATYPE_LABEL"));
/*
        mCALbl = makeJLabel("CATYPE");
*/
        CMSAdminUtil.resetGBC(gbc);
        gbc.insets = new Insets(2*COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(mCALbl, gbc);

        mCABtn = makeJRadioButton("SELFSIGN", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCABtn, gbc);

        mSubBtn = makeJRadioButton("SUBORDINATE", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mSubBtn, gbc);

        ButtonGroup caGroup = new ButtonGroup();
        caGroup.add(mCABtn);
        caGroup.add(mSubBtn);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        CertSetupWizardInfo wizardInfo = (CertSetupWizardInfo)info;
        String str = (String)mCertBox.getSelectedItem();

		/*
        if ((mCASigningCert == null) || (!str.equals(mCASigningCert))) {
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SUBORDINATE_CA);
            return;
        }
		*/

		if ((mCASigningCert != null) && (str.equals(mCASigningCert))) {
			if (mCABtn.isSelected()) {
				wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SELF_SIGNED);
			} else if (mSubBtn.isSelected()) {
				wizardInfo.addEntry(wizardInfo.CA_TYPE,
									wizardInfo.SUBORDINATE_CA);
				}
		} else if ((mCASigningCert != null) && (mServerCert != null)
				   && (str.equals(mServerCert))) {
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SUBORDINATE_CA);
			if (mCABtn.isSelected())
				wizardInfo.setSSLCertLocalCA(Constants.TRUE);
			else if (mSubBtn.isSelected())
				wizardInfo.setSSLCertLocalCA(Constants.FALSE);
		} else if ((mCASigningCert != null) && (mServerCertRadm != null)
				   && (str.equals(mServerCertRadm))) {
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SUBORDINATE_CA);
			if (mCABtn.isSelected())
				wizardInfo.setSSLCertLocalCA(Constants.TRUE);
			else if (mSubBtn.isSelected())
				wizardInfo.setSSLCertLocalCA(Constants.FALSE);
		} else if ((mCASigningCert != null) && (mOCSPSigningCert != null)
				   && (str.equals(mOCSPSigningCert))) {
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SUBORDINATE_CA);
			if (mCABtn.isSelected())
				wizardInfo.setSSLCertLocalCA(Constants.TRUE);
			else if (mSubBtn.isSelected())
				wizardInfo.setSSLCertLocalCA(Constants.FALSE);
        } else if (mOtherCert != null && str.equals(mOtherCert)) {
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SUBORDINATE_CA);
            wizardInfo.setCertSubType(mCertTypeText.getText());
		} else {
            wizardInfo.addEntry(wizardInfo.CA_TYPE, wizardInfo.SUBORDINATE_CA);
        }
    }

    public void itemStateChanged(ItemEvent e) {
        if (e.getSource().equals(mCertBox)) {
            String str = (String)mCertBox.getSelectedItem();
            if (str == null)
                return;

            if (str.equals(mOtherCert)) {
                mCABtn.setEnabled(false);
                mSubBtn.setEnabled(false);
                mCALbl.setEnabled(false);
                mCertType.setEnabled(true);
                mCertTypeText.setEnabled(true);
                mCertTypeText.setBackground(mActiveColor);
            } else {
                mCABtn.setEnabled(true);
                mSubBtn.setEnabled(true);
                mCALbl.setEnabled(true);
                mCertType.setEnabled(false);
                mCertTypeText.setEnabled(false);
                mCertTypeText.setBackground(getBackground());
                if ((mCASigningCert != null) && (str.equals(mCASigningCert)))
                    enableFields(true,"casigning");
                else if ((mCASigningCert != null) && (mOCSPSigningCert != null)
					 && (str.equals(mOCSPSigningCert)))
                    enableFields(true,"ocspsigning");
                else if ((mCASigningCert != null) && (mServerCert != null)
					 && (str.equals(mServerCert)))
                    enableFields(true,"server");
                else if ((mCASigningCert != null) && (mServerCertRadm != null)
					 && (str.equals(mServerCertRadm)))
                    enableFields(true,"server");
			    else
				    enableFields(false,"other");
            }
            CMSAdminUtil.repaintComp(mCertType);
            CMSAdminUtil.repaintComp(mCertTypeText);
        }
    }

    private void enableFields(boolean enable,String type) {
		String label = null;
		String b1 = null;
		String b2 = null;
		if (type.equals("casigning")) {
			label =
				mResource.getString("CERTTYPEWIZARD_TEXT_CATYPE_LABEL");
			b1 =
				mResource.getString("CERTTYPEWIZARD_RADIOBUTTON_SELFSIGN_LABEL");
			b2 = 
				mResource.getString("CERTTYPEWIZARD_RADIOBUTTON_SUBORDINATE_LABEL");
		} else if (type.equals("server")) {
			label =
				mResource.getString("CERTTYPEWIZARD_TEXT_SERVERTYPE_LABEL");
			b1 =
				mResource.getString("CERTTYPEWIZARD_RADIOBUTTON_SERVER_SELFSIGN_LABEL");
			b2 = 
				mResource.getString("CERTTYPEWIZARD_RADIOBUTTON_SERVER_SUBORDINATE_LABEL");
		} else if (type.equals("ocspsigning")) {
			label =
				mResource.getString("CERTTYPEWIZARD_TEXT_OCSPTYPE_LABEL");
			b1 =
				mResource.getString("CERTTYPEWIZARD_RADIOBUTTON_SELFSIGNOCSP_LABEL");
			b2 = 
				mResource.getString("CERTTYPEWIZARD_RADIOBUTTON_SUBORDINATEOCSP_LABEL");
		}

        mCALbl.setEnabled(enable);
        mCALbl.invalidate();
        mCALbl.validate();
		if (label != null) mCALbl.setText(label);
        mCALbl.repaint(1);
        mCABtn.setEnabled(enable);
        mCABtn.invalidate();
        mCABtn.validate();
		if (b1 != null) mCABtn.setText(b1);
        mCABtn.repaint(1);
        mSubBtn.setEnabled(enable);
        mSubBtn.invalidate();
        mSubBtn.validate();
		if (b2 != null) mSubBtn.setText(b2);
        mSubBtn.repaint(1);
    }
}
