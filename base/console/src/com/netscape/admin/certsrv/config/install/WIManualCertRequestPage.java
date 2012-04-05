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
import java.io.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * Manual certificate request page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIManualCertRequestPage extends WBaseManualCertRequestPage implements IWizardPanel {
//    private static final String PANELNAME = "INSTALLMANUALCERTREQUESTWIZARD";
    String mHelpIndex;

    WIManualCertRequestPage(String panelName) {
        super(panelName);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        return super.initializePanel(info);
    }

    public boolean validatePanel() {
        return super.validatePanel();
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
        String certType = null;
        String rawData = "";
        if (mReqType.equals(Constants.PR_CA_SIGNING_CERT)){
            rawData = "profileId=caCACert";
        }else if (mReqType.equals(Constants.PR_SERVER_CERT) ||
                  mReqType.equals(Constants.PR_KRA_TRANSPORT_CERT)){
            rawData = "profileId=caServerCert";
        }else if (mReqType.equals(Constants.PR_OCSP_SIGNING_CERT)){
            rawData = "profileId=caOCSPCert";
        }else if (mReqType.equals(Constants.PR_RA_SIGNING_CERT)){
            rawData = "profileId=caRACert";
        }else {
            setErrorMessage("Wrong cert request type!");
            return false;
        }

        if (mReqFormat.equals(ConfigConstants.PR_REQUEST_PKCS10)){
            rawData = rawData+"&cert_request_type=pkcs10";
            rawData = rawData+"&cert_request="+mReq;
        } else {
            rawData = rawData+"&cert_request_type=cmc";
            rawData = rawData+"&cert_request="+mReq;
            // test full response, but we don't really need it
            // data.put("fullResponse", "true");
        }

        startProgressStatus();
        boolean ready = send(mHost, Integer.parseInt(mPort),
          "/ca/ee/ca/profileSubmit", rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage();
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
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_REQUEST_SUCCESS;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
            rawData = rawData+"&"+Constants.PR_CERTIFICATE_TYPE+"="+mReqType;
            rawData = rawData+"&"+mReqType+ConfigConstants.PR_REQUEST_ID+"="+
              reqID;
            rawData = rawData+"&"+ConfigConstants.CA_EEPORT+"="+
              mPortText.getText();
            rawData = rawData+"&"+ConfigConstants.CA_EETYPE+"="+
              wizardInfo.getCMEEType();
            rawData = rawData+"&"+ConfigConstants.CA_HOST+"="+
              mHostText.getText();

            startProgressStatus();
            ready = send(rawData, wizardInfo);
            endProgressStatus();

            if (!ready) {
                String str = getErrorMessage();
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

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void back_cb(WizardInfo info) {
		// clear up the status
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
		wizardInfo.remove(wizardInfo.getCertType()+ConfigConstants.PR_CERT_REQUEST+"Status");
		wizardInfo.remove(wizardInfo.getCertRequest()+"Error");
		wizardInfo.remove(wizardInfo.getCertType()+ConfigConstants.PR_REQUEST_ID);
    }

    protected void init() {
        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
