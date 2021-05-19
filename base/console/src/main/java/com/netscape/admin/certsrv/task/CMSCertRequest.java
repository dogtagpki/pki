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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Hashtable;

import com.netscape.admin.certsrv.keycert.CertSetupWizardInfo;
import com.netscape.management.client.comm.CommManager;
import com.netscape.management.client.comm.CommRecord;
import com.netscape.management.client.comm.HttpManager;
import com.netscape.management.client.util.Debug;

/**
 * Perform certificate request in certificate setup wizard.
 *
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 */
public class CMSCertRequest extends CGITask {

    /*==========================================================
     * variables
     *==========================================================*/
    private CertSetupWizardInfo mWizardInfo;
	private String mPolicyMsg = null;

	/*==========================================================
     * constructors
     *==========================================================*/
	public CMSCertRequest() {
		super();
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void initialize(CertSetupWizardInfo info) {
        Debug.println("CMSRequestCert: initialize()");
        _consoleInfo = info.getAdminConsoleInfo();

        // the results coming back from the daemon will be added to the
        // wizard information.
        mWizardInfo = info;
    }

    /**
     * Collect the data in name value pairs format and then send them to the
     * cgi process.
	 */
	public boolean requestCert(Hashtable<String, Object> data) {
	    boolean status = false; // return value

		try {
			status = run(data);
		} catch (Exception e) {
			Debug.println("Unexpected Error"+e.toString());
			status = false;
		}
		Debug.println("CMSRequestCert: requestCert() after run status=" +
					  status + " mSuccess=" + mSuccess);

		return mSuccess;
	}

    /**
	 *	the operation is finished after we receive the http stream
	 */
    @Override
    public void replyHandler(InputStream response, CommRecord cr) {
        mSuccess = false;

        try {
			BufferedReader rspStream =
				new BufferedReader(new InputStreamReader(response, "UTF8"));
			String rspStr;

			Debug.println("CMSRequestCert: replyHandler() - start");
			mErrorMsg = mResource.getString("REQUESTRESULTWIZARD_TEXT_ERRORDESC_LABEL");
			while ((rspStr = rspStream.readLine()) != null && !mSuccess)
			{
				Debug.println("RequestCert: replyHandler() - read [" + rspStr + "]");
				// NMC_ messages are parsed, but not shown to the user
				parse2(rspStr);
			}
			mErrorMsg = mErrorMsg +
				mResource.getString("REQUESTRESULTWIZARD_TEXT_ERROREND_LABEL");
			String requestStatus =mWizardInfo.getRequestStatus();
			if ((mWizardInfo.getRequestError() != null) &&
				mWizardInfo.getRequestError().equals("true")) {
				mWizardInfo.setRequestError(mErrorMsg);
				mErrorMsg = null;
				mSuccess = true;
			} else if (requestStatus == null) {
				// agent port, Unauthorizied access
				mErrorMsg = mResource.getString("CGITASK_DIALOG_WRONGSERVER_MESSAGE");
			} else if (requestStatus.equals("5")) {
				// rejected
				if (mPolicyMsg == null) {
					mWizardInfo.setRequestError(mResource.getString("REQUESTRESULTWIZARD_TEXT_NODETAIL_LABEL"));
				} else {
				    mWizardInfo.setRequestError(mPolicyMsg);
					mPolicyMsg = null;
				}
				mSuccess = true;
			}
			// Use the same format for other status:success,pending,svcPending
		} catch (Exception e) {
			Debug.println("RequestCert.Exception : " + e.toString());
		}

		Debug.println("RequestCert.replyHandler: finished, mSuccess=" +
					  mSuccess);

        finish();
    }

       private void parse2(String s)
       {
               int iIndex;
               Debug.println("Parse2 input: " + s);
               if ((iIndex=s.indexOf("errorCode")) != (-1))
               {
                       String errorCode = s.substring(s.indexOf("\"") + 1,
                         s.lastIndexOf("\""));
                       Debug.println("errorCode: " + errorCode);
                       if (errorCode.equals("2")) { // pending
                         mWizardInfo.setRequestError("false");
                         mSuccess = true;
             mWizardInfo.setRequestStatus("0");
                       } else if (errorCode.equals("1")) { // error
                         mWizardInfo.setRequestError("true");
             mWizardInfo.setRequestStatus("5");
                         mSuccess = false;
                       } else {
                         mWizardInfo.setRequestError("true");
             mWizardInfo.setRequestStatus("0");
                         mSuccess = false;
                       }
               }
               else if ((iIndex=s.indexOf("requestList.requestId")) != (-1))
               {
                       String requestId = s.substring(s.indexOf("\"") + 1,
                         s.lastIndexOf("\""));
                       Debug.println("requestId: " + requestId);
                       mWizardInfo.setRequestID(requestId);
               }
               else if ((iIndex=s.indexOf("errorReason")) != (-1))
               {
                       String errorReason = s.substring(s.indexOf("\"") + 1,
                         s.lastIndexOf("\""));
                       Debug.println("errorReason: " + errorReason);
                       mErrorMsg = mErrorMsg + "\n    " + errorReason;
               }
       }

	/**
	 * Send an http request to the server. Return true if we're sure it
	 * succeeded, otherwise false.
	 */
	boolean run(Hashtable<String, Object> args) {

		String fullCmd = mWizardInfo.getCMEEType() + "://" +
			mWizardInfo.getCMHost() + ":" +
			mWizardInfo.getCMEEPort() + "/ca/ee/ca/profileSubmit";

		HttpManager h = new HttpManager();
		// tell the http manager to use UTF8 encoding
		CommManager.setSendUTF8(true);

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

}



