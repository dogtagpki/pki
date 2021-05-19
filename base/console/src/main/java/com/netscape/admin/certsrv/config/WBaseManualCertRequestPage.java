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

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.Hashtable;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.config.install.InstallWizardInfo;
import com.netscape.admin.certsrv.task.CMSConfigCert;
import com.netscape.admin.certsrv.task.CMSRequestCert;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.Debug;

/**
 * Certificate wizard page
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
public class WBaseManualCertRequestPage extends WizardBasePanel {

    public static final String SERVER_CERT = "server";
    public static final String CLIENT_CERT = "client";
    public static final String CA_CERT = "ca";
    public static final String RA_CERT = "ra";
    public static final String OCSP_CERT = "ocsp";
    public static final String OBJECT_SIGNING_CERT = "objSignClient";
    public static final String OTHER_CERT = "other";
    public static final String ROUTER_CERT = "router"; // deprecated
    public static final String CEP_CERT = "CEP-Request";

    public static final String CERT_TYPE = "certType";
    public static final String PKCS10_REQUEST = "pkcs10Request";
	public static final String CMC_REQUEST = "cmcRequest";

	protected JButton mCopy;
    protected JTextArea mText;
    protected String mPanelName, mDir;
    protected JTextArea mFileName;
    protected JTextArea mDesc;

    protected JTextField mHostText, mPortText;
    protected JLabel mHostLbl, mPortLbl;
    protected JLabel mSSLText;
    protected JCheckBox mSSL; // ssl or not
    protected String mHost, mPort;
    protected JLabel mSendNowText;
    protected JCheckBox mSendNowBox;
	protected Color mActiveColor;
    public static final int MAX_PORT = 65535;
    public static final int MIN_PORT = 1;
	protected String mReq = null;
	protected String mReqType = null;
	protected String mReqFormat = null;

    public WBaseManualCertRequestPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

		mReqType = wizardInfo.getCertType();
		mReqFormat = wizardInfo.getReqFormat(mReqType);

		if (mReqType.equals(Constants.PR_CA_SIGNING_CERT)){
			mReq = (String)wizardInfo.get(ConfigConstants.CA_CERT_REQUEST);
		}else if (mReqType.equals(Constants.PR_SERVER_CERT) ){
			mReq = (String)wizardInfo.get(ConfigConstants.SSL_CERT_REQUEST);
		}else if (mReqType.equals(Constants.PR_KRA_TRANSPORT_CERT)){
			mReq = (String)wizardInfo.get(ConfigConstants.KRA_CERT_REQUEST);
		}else if (mReqType.equals(Constants.PR_OCSP_SIGNING_CERT)){
			mReq = (String)wizardInfo.get(ConfigConstants.OCSP_CERT_REQUEST);
		}else if (mReqType.equals(Constants.PR_RA_SIGNING_CERT)){
			mReq = (String)wizardInfo.get(ConfigConstants.RA_CERT_REQUEST);
			Debug.println("no request got from ra stage");
		}else {
			setErrorMessage("Wrong cert request type!");
			return false;
		}

		if (mReq == null || mReq.equals("")){
			mReq = wizardInfo.getCertRequest();
		}
		if (mReqFormat.equals(ConfigConstants.PR_REQUEST_PKCS10)){

			// Break the long single line:header,64 byte lines,trailer
			// Assuming this is the only format we generate.
			String CERT_NEW_REQUEST_HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----";
			String CERT_NEW_REQUEST_TRAILER = "-----END NEW CERTIFICATE REQUEST-----";
			int head = mReq.indexOf(CERT_NEW_REQUEST_HEADER);
			int trail = mReq.indexOf(CERT_NEW_REQUEST_TRAILER);
        	String unwrapped =
				mReq.substring(head+CERT_NEW_REQUEST_HEADER.length(),trail);
			String str = CERT_NEW_REQUEST_HEADER + "\n";
			int len = unwrapped.length();
			for (int i = 0; i < len; i=i+64){
				if (i+64 < len)
					str = str + unwrapped.substring(i,i+64) +"\n";
				else
					str = str + unwrapped.substring(i,len) +"\n";
		    }
			str = str + CERT_NEW_REQUEST_TRAILER;
			mReq = str;
	    } else if (mReqFormat.equals(ConfigConstants.PR_REQUEST_CMC)){
			String str = "";
			int len = mReq.length();
			for (int i = 0; i < len; i=i+64){
				if (i+64 < len)
					str = str + mReq.substring(i,i+64) +"\n";
				else
					str = str + mReq.substring(i,len) +"\n";
		    }
			mReq = str;
		}

		if (mReq == null)
			return false;
        mText.setText(mReq);

        mText.selectAll();
        setBorder(makeTitledBorder(mPanelName));

        mDir = wizardInfo.getCertRequestDir();
        String str = mResource.getString(mPanelName+"_TEXT_FILELOC_LABEL")+mDir+".";
        mFileName.setText(str);

        if (mSendNowBox.isSelected())
            enableFields(true, mActiveColor);
        else
            enableFields(false, getBackground());

		String host = wizardInfo.getCMHost();
		if (host != null && !host.equals(""))
			mHostText.setText(host);
		String port = wizardInfo.getCMEEPort();
		if (port != null && !port.equals(""))
			mPortText.setText(port);

		String portType = wizardInfo.getCMEEType();
		if (portType != null && portType.equals("http"))
			mSSL.setSelected(false);

		String desc = "";
		if (!wizardInfo.isNewRequest()) {
			desc = mResource.getString(mPanelName+"_TEXT_IGNOR_LABEL")+
						  "\n";
		}
        String certType = wizardInfo.getCertType();
		if (mReqFormat.equals(ConfigConstants.PR_REQUEST_PKCS10)) {
		    desc = desc + mResource.getString( mPanelName+"_TEXT_DESC_LABEL");
		} else if (mReqFormat.equals(ConfigConstants.PR_REQUEST_CMC)) {
			desc = desc + mResource.getString(
							mPanelName+"_TEXT_CMCDESC_LABEL");
		}
		mDesc.setText(desc);

        return true;
    }

    public boolean validatePanel() {
        if (!mSendNowBox.isSelected()) {
            mHost = "";
            mPort = "";
            return true;
        }

        mHost = mHostText.getText().trim();
        mPort = mPortText.getText().trim();
        if (mHost.equals("")) {
            setErrorMessage("BLANKHOST");
            return false;
        }
        if (mPort.equals("")) {
            setErrorMessage("BLANKPORT");
            return false;
        }

        try {
            int portnumber = Integer.parseInt(mPort);
            if (portnumber < MIN_PORT || portnumber > MAX_PORT) {
                setErrorMessage("OUTOFRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            setErrorMessage("INVALIDPORT");
            return false;
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
		if (!mSendNowBox.isSelected())
			return true;

        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
		if (mHost != null && !mHost.equals(""))
			wizardInfo.setCMHost(mHost);
		if (mPort != null && !mPort.equals(""))
			wizardInfo.setCMEEPort(mPort);
		if (mSSL.isSelected())
			wizardInfo.setCMEEType("https");
		else
			wizardInfo.setCMEEType("http");

        CMSRequestCert requestCertCgi = new CMSRequestCert();
        requestCertCgi.initialize(wizardInfo);
        Hashtable<String, Object> data = new Hashtable<>();

		String certType = null;
		if (mReqType.equals(Constants.PR_CA_SIGNING_CERT)){
                        data.put("profileId", "caCACert");
		}else if (mReqType.equals(Constants.PR_SERVER_CERT) ||
				  mReqType.equals(Constants.PR_KRA_TRANSPORT_CERT)){
                        data.put("profileId", "caServerCert");
		}else if (mReqType.equals(Constants.PR_OCSP_SIGNING_CERT)){
                        data.put("profileId", "caOCSPCert");
		}else if (mReqType.equals(Constants.PR_RA_SIGNING_CERT)){
                        data.put("profileId", "caRACert");
		}else {
			setErrorMessage("Wrong cert request type!");
			return false;
		}

		if (mReqFormat.equals(ConfigConstants.PR_REQUEST_PKCS10)){
			data.put("cert_request_type", "pkcs10");
			data.put("cert_request", mReq);
		} else {
			data.put("cert_request_type", "cmc");
			data.put("cert_request", mReq);
			// test full response, but we don't really need it
			// data.put("fullResponse", "true");
		}

        startProgressStatus();
        boolean ready = requestCertCgi.requestCert(data);
        endProgressStatus();

        if (!ready) {
            String str = requestCertCgi.getErrorMessage();
            if (str.equals(""))
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
			return ready;
        }
		wizardInfo.setRequestSent(ready);

		//save the stage
		String reqID = wizardInfo.getRequestID();
		String reqStatus = wizardInfo.getRequestStatus();
        String reqError = wizardInfo.getRequestError();

		wizardInfo.setX509RequestID(reqID);
        wizardInfo.setX509RequestStatus(reqStatus);
        if (reqError != null)
            wizardInfo.setX509RequestError(reqError);

        // rejected request should not be saved as requestSuccStage!!
		if ( (reqID != null) && !reqID.equals("") &&
			 (wizardInfo.getRequestError() == null) &&
			 (reqStatus.equals(Constants.PR_REQUEST_SUCCESS)
               || reqStatus.equals(Constants.PR_REQUEST_PENDING)
				|| reqStatus.equals(Constants.PR_REQUEST_SVC_PENDING)) ) {
            data  = new Hashtable<>();

            ConsoleInfo consoleInfo = wizardInfo.getAdminConsoleInfo();
            data.put(ConfigConstants.TASKID, TaskId.TASK_REQUEST_SUCCESS);
            data.put(ConfigConstants.OPTYPE, OpDef.OP_MODIFY);
            data.put(ConfigConstants.PR_SERVER_ROOT,
              consoleInfo.get(ConfigConstants.PR_SERVER_ROOT));
            data.put(ConfigConstants.PR_CERT_INSTANCE_NAME,
              consoleInfo.get(ConfigConstants.PR_CERT_INSTANCE_NAME));
            data.put(Constants.PR_CERTIFICATE_TYPE, mReqType);
			data.put(mReqType+ConfigConstants.PR_REQUEST_ID, reqID);

            data.put(ConfigConstants.CA_EEPORT, mPortText.getText());
            data.put(ConfigConstants.CA_EETYPE, wizardInfo.getCMEEType());
            data.put(ConfigConstants.CA_HOST, mHostText.getText());
            startProgressStatus();
            CMSConfigCert configCertCgi = new CMSConfigCert();
            configCertCgi.initialize(wizardInfo);
            ready = configCertCgi.configCert(data);
            endProgressStatus();

            if (!ready) {
                String str = configCertCgi.getErrorMessage();
                if (str.equals("")) {
                    String errorMsg = mResource.getString(
                      mPanelName+"_ERRORMSG");
                    setErrorMessage(errorMsg);
                } else
                    setErrorMessage(str);
                return ready;
            }
		}
        return ready;
    }

    @Override
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        mDesc = createTextArea(mResource.getString(
          mPanelName+"_TEXT_DESC_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mDesc, gbc);

        mActiveColor = mDesc.getBackground();

        mText = new JTextArea(null, null, 10, 10);
        //mText.setLineWrap(true);
        //mText.setWrapStyleWord(true);
		mText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(mText,
          JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
          JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setPreferredSize(new Dimension(50, 50));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        gbc.weightx = 1.0;
        gbc.weighty = 0.5;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(scrollPane, gbc);

        mCopy = makeJButton("COPY");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mCopy, gbc);

        mFileName = createTextArea("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mFileName, gbc);

        JLabel dummy = new JLabel(" ");
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weighty = 0.5;
        gbc.fill = GridBagConstraints.BOTH;
        add(dummy, gbc);

        mSendNowBox = makeJCheckBox("SENDNOW", false);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSendNowBox, gbc);

        mSendNowText = new JLabel(mResource.getString(
            mPanelName + "_TEXT_SENDNOW_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSendNowText, gbc);

        mHostLbl = makeJLabel("HOST");
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mHostLbl, gbc);

        mHostText = makeJTextField(30);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mHostText, gbc);
        mActiveColor = mHostText.getBackground();

        mPortLbl = makeJLabel("PORT");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mPortLbl, gbc);

        mPortText = makeJTextField(10);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        add(mPortText, gbc);

        mSSLText = new JLabel(mResource.getString(
            mPanelName+"_TEXT_SSL_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSSLText, gbc);

        mSSL = makeJCheckBox("SSL", true);
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 4*COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(mSSL, gbc);

        JLabel label = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(label, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    @Override
    public void actionPerformed(ActionEvent event) {
        if (event.getSource().equals(mCopy)) {
            mText.copy();
        }
        if (mSendNowBox.isSelected()) {
            enableFields(true, mActiveColor);
        } else {
            enableFields(false, getBackground());
        }
    }

    protected void enableFields(boolean enabled, Color color) {
        mSendNowText.setEnabled(enabled);
        //mSendNowText.setEditable(enabled);
        CMSAdminUtil.repaintComp(mSendNowText);
        mHostLbl.setEnabled(enabled);
        mPortLbl.setEnabled(enabled);
        mHostText.setEnabled(enabled);
        mHostText.setEditable(enabled);
        mHostText.setBackground(color);
        mPortText.setEnabled(enabled);
        mPortText.setEditable(enabled);
        mPortText.setBackground(color);
        CMSAdminUtil.repaintComp(mHostLbl);
        CMSAdminUtil.repaintComp(mHostText);
        CMSAdminUtil.repaintComp(mPortLbl);
        CMSAdminUtil.repaintComp(mPortText);
		mSSLText.setEnabled(enabled);
		//mSSLText.setEditable(enabled);
        CMSAdminUtil.repaintComp(mSSLText);
		mSSL.setEnabled(enabled);
		//mSSL.setEditable(enabled);
		//mSSL.setBackground(color);
        CMSAdminUtil.repaintComp(mSSL);

    }
}
