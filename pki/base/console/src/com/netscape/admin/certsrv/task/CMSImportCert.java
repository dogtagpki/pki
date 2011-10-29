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
package com.netscape.admin.certsrv.task;

import java.util.*;
import javax.swing.*;
import com.netscape.management.client.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.config.install.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.topology.*;
import com.netscape.management.client.comm.*;
import java.net.*;
import java.io.*;
import netscape.ldap.*;
import netscape.ldap.util.*;

/**
 * Perform certificate import.
 *
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 */
public class CMSImportCert extends CGITask {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CGITASK"; 
	private String mCgiTask = null; // CGI task to call
    private InstallWizardInfo mWizardInfo;
	private String mPolicyMsg = null;
	
	// To support Thawte's header and footer
    public static final String BEGIN_PKCS7_HEADER = 
		"-----BEGIN PKCS #7 SIGNED DATA-----";
    public static final String END_PKCS7_HEADER = 
		"-----END PKCS #7 SIGNED DATA-----";
    public static final String BEGIN_HEADER = "-----BEGIN CERTIFICATE-----";
    public static final String END_HEADER = "-----END CERTIFICATE-----";

	/*==========================================================
     * constructors
     *==========================================================*/
	public CMSImportCert() {
		super();
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void initialize(InstallWizardInfo info) {
        Debug.println("CMSImportCert: initialize()");
        _consoleInfo = info.getAdminConsoleInfo();

        // the results coming back from the daemon will be added to the 
        // wizard information.
        mWizardInfo = info;
    }
    
    /**
     * Collect the data in name value pairs format and then send them to the 
     * cgi process.
	 */
	public boolean importCert(Hashtable data) {
	    boolean status = false; // return value

		try {
			status = run(data);
		} catch (Exception e) {
			Debug.println("Unexpected Error"+e.toString());
			status = false;
		}
		Debug.println("CMSImportCert: ImportCert() after run status=" +
					  status + " mSuccess=" + mSuccess);

		return mSuccess;
	}
   
    /**
	 *	the operation is finished after we receive the http stream
	 */
    public void replyHandler(InputStream response, CommRecord cr) {
        mSuccess = false;

        try {
			BufferedReader rspStream =
				new BufferedReader(new InputStreamReader(response, "UTF8"));
			String rspStr;

			Debug.println("CMSImportCert: replyHandler() - start");

			mWizardInfo.setImportError("");
			while ((rspStr = rspStream.readLine()) != null && !mSuccess)
			{
				Debug.println("ImportCert: replyHandler() - read [" + rspStr + "]");
				// NMC_ messages are parsed, but not shown to the user
				parse(rspStr);
			}

			String importError = mWizardInfo.getImportError();
			if (importError != null && !importError.equals("")) {
				mErrorMsg = importError;
				mSuccess = false;
			} else if (!mSuccess) {
				// agent port, Unauthorizied access
				mErrorMsg = mResource.getString("CGITASK_DIALOG_WRONGSERVER_MESSAGE");
			}
		} catch (Exception e) {
			Debug.println("ImportCert.Exception : " + e.toString());
		}
		
		Debug.println("ImportCert.replyHandler: finished, mSuccess=" +
					  mSuccess);

        finish();
    }
    
    /**
	 * return the value for the given keyword in the reply
	 */
	private void parse(String s) {
		String sName;
		String sValue = null;
		int iIndex;

		Debug.println("Parse input: " + s);

		if ((iIndex=s.indexOf("status = ")) != (-1))
		{
			sName = s.substring(iIndex + 10).trim();
			if ((iIndex = sName.indexOf("\"")) != (-1))
				sValue = sName.substring(0,iIndex);

			Debug.println("Parse input: name=" + sName + " output="
						  + sValue + " index=" + iIndex);
			if (sValue != null && !sValue.equals("")) {
				if (sValue.equals(ConfigConstants.PENDING_STRING) ||
					sValue.equals(ConfigConstants.APPROVED_STRING) ||
					sValue.equals(ConfigConstants.SVC_PENDING_STRING)) {
					mWizardInfo.setImportError("Request " +
						mWizardInfo.getRequestID() + 
						" is " + sValue + 
						".\nYou can contact an authorized agent or local administrator for further assistance by referring to the request ID.");
					mSuccess = true;
				} else if (sValue.equals(ConfigConstants.CANCELED_STRING) ||
					   sValue.equals(ConfigConstants.REJECTED_STRING)  ) {
					String stage =
						getStage(mWizardInfo.getCertType());
					if (stage != null)
						mWizardInfo.put(stage, ConfigConstants.FALSE);
					mWizardInfo.setImportError("Request " +
						mWizardInfo.getRequestID() + 
						" is " + sValue + 
						".\nYou can contact an authorized agent or local administrator for further assistance by referring to the request ID." + "\nYou will be able to regenerate a new request if you click back." );
					mSuccess = true;
				}
			}
		}
		else if ((iIndex=s.indexOf("pkcs7ChainBase64 = ")) != (-1))
		{
			sName = s.substring(iIndex + 20).trim();
			if ((iIndex = sName.indexOf("\"")) != (-1))
				sValue = sName.substring(0,iIndex);

			Debug.println("Parse input: name=" + sName + " output="
						  + sValue + " index=" + iIndex);
			if (sValue != null && !sValue.equals("")) {
				String val = sValue.trim();
			    String result = normalizeCertStr(val);
				Debug.println("After removing all the carriage returns:");
				Debug.println(result);
        		mWizardInfo.setPKCS10(result);	
				mSuccess = true;
				
			}
		}
		else if ((iIndex=s.indexOf("unexpectedError = ")) != (-1))
		{
			sName = s.substring(iIndex + 19).trim();
			if ((iIndex = sName.indexOf("\"")) != (-1))
				sValue = sName.substring(0,iIndex);

			Debug.println("Parse input: name=" + sName + " output="
						  + sValue + " index=" + iIndex);
			if (sValue != null && !sValue.equals("")) {
				mErrorMsg = mErrorMsg + "\n    " + sValue;
				mWizardInfo.setRequestError("true");
			}
		}
		else if ((iIndex=s.indexOf("errorDetails = ")) != (-1))
		{
			sName = s.substring(iIndex + 16).trim();
			if ((iIndex = sName.indexOf("\"")) != (-1))
				sValue = sName.substring(0,iIndex);

			Debug.println("Parse input: name=" + sName + " output="
						  + sValue + " index=" + iIndex);
			if (sValue != null && !sValue.equals("")) {
				mErrorMsg = mErrorMsg + "\n    " + sValue;
				mWizardInfo.setRequestError("true");
			}
		}
		else if ((iIndex=s.indexOf("result.recordSet.length = ")) != (-1))
		{
			sName = s.substring(iIndex + 27).trim();
			if ((iIndex = sName.indexOf("\"")) != (-1))
				sValue = sName.substring(0,iIndex);

			Debug.println("Parse input: name=" + sName + " output="
						  + sValue + " index=" + iIndex);
			if (sValue != null && !sValue.equals("") && !sValue.equals("0")) {
				mErrorMsg = mErrorMsg + mResource.getString("REQUESTRESULTWIZARD_TEXT_DETAIL_LABEL");;
			}
		}
		else if ((iIndex=s.indexOf("errorDescription = ")) != (-1))
		{
			sName = s.substring(iIndex + 20).trim();
			if ((iIndex = sName.indexOf("\"")) != (-1))
				sValue = sName.substring(0,iIndex);

			Debug.println("Parse input: name=" + sName + " output="
						  + sValue + " index=" + iIndex);
			if (sValue != null && !sValue.equals("")) {
				mErrorMsg = mErrorMsg + "\n    " + sValue;
			}
		}
		else if ((iIndex=s.indexOf("record.policyMessage=")) != (-1))
		{
			sName = s.substring(iIndex + 22).trim();
			if ((iIndex = sName.indexOf("\"")) != (-1))
				sValue = sName.substring(0,iIndex);

			Debug.println("Parse input: name=" + sName + " output="
						  + sValue + " index=" + iIndex);
			if (sValue != null && !sValue.equals("")) {
				if (mPolicyMsg == null)
					mPolicyMsg = "    " + sValue;
				else
					mPolicyMsg = mPolicyMsg + "\n    " + sValue;
			}
		}
			
		Debug.println("Parse finished");
    }

	/**
	 * Send an http request to the server. Return true if we're sure it
	 * succeeded, otherwise false.
	 */
	boolean run(Hashtable args) {

		String fullCmd = mWizardInfo.getCMEEType() + "://" +
			mWizardInfo.getCMHost() + ":" +
			mWizardInfo.getCMEEPort() + "/checkRequest";

		HttpManager h = new HttpManager();
		// tell the http manager to use UTF8 encoding
		h.setSendUTF8(true);

		try {
			mSuccess = false;
			mFinished = false;
			
			ByteArrayInputStream data = null;
			if (args != null && !args.isEmpty())
				data = encode(args);
			Debug.println( "Posting " + fullCmd );
			// tell the http manager to notify us immediately of replies
			// if we're using async mode
			int flags = 0;
			CommRecord postResult = null;
			if (data == null)
				postResult = h.post(new URL(fullCmd), this, null, null, 0,
					   flags);
			else
				postResult = h.post(new URL(fullCmd), this, null, data, data.available(),
					   flags);

			/*
			AdmTask admTask = new AdmTask(new URL(fullCmd),null,null);
			admTask.setArguments(args);
			admTask.exec(h);
			*/

			awaitSuccess();

			Object postStatus = postResult.getStatus();
			//Debug.println("status: " + postStatus);
			if (postStatus != null &&
				postStatus.toString().equals(CommRecord.ERROR)) {
				// If it happens to be it's not CMS server who is listening
				// e.g. the cms agent port or yahoo server
				// you may get here
				mErrorMsg = mResource.getString("CGITASK_DIALOG_WRONGSERVER_MESSAGE");
			}

			Debug.println( "Command executed: " + fullCmd );
		} catch (Exception e) {
			// This is very fragile. We have to handle it case by case.
			// Handled the ones that I know of properly, but there may
			// be other cases that I don't know, display the exception
			// detail.
			String detail = e.toString();
			if (detail == null || detail.trim().equals(""))
				detail = "No detail of the exception provided.";
			if ( e instanceof java.net.ConnectException ) {
				mErrorMsg = mResource.getString("CGITASK_DIALOG_CMSDOWN_MESSAGE");
				//CMSAdminUtil.showMessageDialog(mResource,
                //        PREFIX, "CMSDOWN", CMSAdminUtil.ERROR_MESSAGE);
			} else if ( e instanceof java.net.NoRouteToHostException ) {
				// java.net.NoRouteToHostException: Connection timed out
				// It takes 3-4 mins to time out, looks like hang to impatient
				// ones. https://www.netscape.com:443
                mErrorMsg =
                    mResource.getString("CGITASK_DIALOG_CMSDOWN_MESSAGE")
;
			} else if ( e instanceof java.net.SocketException ) {
                if (detail.indexOf("Socket write failed") > -1){
					// retry
					run(args);
				} else if ((detail.indexOf("Connection shutdown") > -1) ||
						   (detail.indexOf("Connection timed out") > -1) ) {
					// java.net.NoRouteToHostException: Connection timed out
					// double insurance
					mErrorMsg = 
						mResource.getString("CGITASK_DIALOG_CMSDOWN_MESSAGE");
				} else {
                    // need to determine case by case
					mErrorMsg = 
						mResource.getString("CGITASK_DIALOG_CMSDOWN_MESSAGE")+ " java.net.SocketException: " + detail;
				}

			} else if ( e instanceof java.io.IOException ) {
                if (e.toString().indexOf("Broken pipe") > -1){
                    // broken pipe, retry
                    run(args);
                } else if (detail.indexOf("Unknown public-key algorithm")
> -1) {
                    mErrorMsg =
                        mResource.getString("CGITASK_DIALOG_UNKNOWNALG_MESSAGE")
;
                } else if (detail.indexOf("End of input") > -1) {
					// http://www.netscape.com:80/enrollment
                    mErrorMsg =
                        mResource.getString("CGITASK_DIALOG_CMSDOWN_MESSAGE")
;
                } else if (detail.indexOf("Certificate fingerprint =") > -1) {
					// reject the cms certificate
                    mErrorMsg =
                        mResource.getString("CGITASK_DIALOG_REJECTCERT_MESSAGE");
                } else {
                    // need to determine case by case
                    mErrorMsg =
                        mResource.getString("CGITASK_DIALOG_CMSDOWN_MESSAGE"
) + " java.io.IOException: " + detail;
                }
			} else {
                // need to determine case by case
                mErrorMsg =
                    mResource.getString("CGITASK_DIALOG_CMSDOWN_MESSAGE") 
+ " Exception: " + detail;
            }
			Debug.println( "Command " + fullCmd  + " failed: " + e );
		}
		return mSuccess;
	}

	String getStage(String reqType){
        if (reqType.equals(Constants.PR_CA_SIGNING_CERT)){ 
			return ConfigConstants.STAGE_CA_REQ_SUCCESS;
		}else if (reqType.equals(Constants.PR_SERVER_CERT)){
			return ConfigConstants.STAGE_SSL_REQ_SUCCESS;
		}else if (reqType.equals(Constants.PR_KRA_TRANSPORT_CERT)){
			return ConfigConstants.STAGE_KRA_REQ_SUCCESS;
		}else if (reqType.equals(Constants.PR_RA_SIGNING_CERT)){
			return ConfigConstants.STAGE_RA_REQ_SUCCESS;
		}else if (reqType.equals(Constants.PR_OCSP_SIGNING_CERT)){
			return ConfigConstants.STAGE_OCSP_REQ_SUCCESS;
		}else
			return null;
	}


    public static String normalizeCertStr(String s) {
        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                continue;
            } else if (s.charAt(i) == '\r') {
                continue;
            } else if (s.charAt(i) == '\\' && s.charAt(i+1) == 'r') {
				i++;
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            } else if (s.charAt(i) == ' ') {
                continue;
            }
            val += s.charAt(i);
        }
        return val;
    }

}


