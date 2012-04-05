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
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
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
 * Perform certificate server configuration.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSConfigCert extends CGITask {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CMSCONFIGCERT";

    public static final String CONFIG_CERT_CGI = "Tasks/Operation/config-cert";

	//private boolean mSuccess = false; // status of last executed CGI
	//private Hashtable mCgiResponse = null; // holds parsed contents of CGI return
	private String mCgiTask = null; // CGI task to call
    private InstallWizardInfo mWizardInfo;

	/*==========================================================
     * constructors
     *==========================================================*/
	public CMSConfigCert() {
		super();
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void initialize(InstallWizardInfo info) {
        _consoleInfo = info.getAdminConsoleInfo();

        // the results coming back from the daemon will be added to the
        // wizard information.
        mWizardInfo = info;

		setForceBasicAuth(true);
    }

    /**
     * Collect the data in name value pairs format and then send them to the
     * cgi process.
	 */
	public boolean configCert(Hashtable data) {
        JFrame mActiveFrame = UtilConsoleGlobals.getActivatedFrame();
        if (_consoleInfo.get("AdminUsername") == null)
            _consoleInfo.put("AdminUsername", _consoleInfo.getAuthenticationDN());
        Debug.println("AdminUsername = " + _consoleInfo.get("AdminUsername"));

        if (_consoleInfo.get("AdminUserPassword") == null)
            _consoleInfo.put("AdminUserPassword",
                             _consoleInfo.getAuthenticationPassword());
        Debug.println("AdminUserPassword = " + _consoleInfo.get("AdminUserPassword"));
        data.put("AdminUserPassword", _consoleInfo.getAuthenticationPassword());
        _consoleInfo.put("arguments", data);

		// Send Random value for RNG entropy
        data.put(ConfigConstants.PR_CMS_SEED, new Long(WizardBasePanel.mSeed).toString());

	    boolean status = false; // return value

        Cursor cursor = mActiveFrame.getCursor();
        int type = cursor.getType();
        cursor = new Cursor(Cursor.WAIT_CURSOR);
        mActiveFrame.setCursor(cursor);

		try {
			status = super.run(null, CONFIG_CERT_CGI);
		} catch (Exception e) {
			Debug.println("Unexpected Error"+e.toString());
			status = false;
		}
		Debug.println("CMSConfigCert: configCert() after run status=" +
					  status + " mSuccess=" + mSuccess);

        if (!mSuccess) {
        Debug.println("Show error dialog");
            String errorMsg = getErrorMessage();
/*
            if (errorMsg == null || errorMsg.equals(""))
                CMSAdminUtil.showMessageDialog(mActiveFrame, mResource, PREFIX,
                    "SYSTEMERROR", CMSAdminUtil.ERROR_MESSAGE);
            else
                JOptionPane.showMessageDialog(mActiveFrame, errorMsg,
                  "Error", CMSAdminUtil.ERROR_MESSAGE,
                  CMSAdminUtil.getImage(CMSAdminResources.IMAGE_ERROR_ICON));
*/
        }

        cursor = new Cursor(type);
        mActiveFrame.setCursor(cursor);

		return mSuccess;
	}

    /**
	 *	the operation is finished after we receive the http stream
	 */
    public void replyHandler(InputStream response, CommRecord cr) {
        mSuccess = false;
/*
		if (mCgiResponse != null)
			mCgiResponse.clear();
*/

        try {
			BufferedReader rspStream =
				new BufferedReader(new InputStreamReader(response, "UTF8"));
			String rspStr;

			Debug.println("CMSConfigCert: replyHandler() - start");
			while ((rspStr = rspStream.readLine()) != null)
			{
				Debug.println("ConfigCert: replyHandler() - read [" + rspStr + "]");
				// NMC_ messages are parsed, but not shown to the user
				/*
				if (_statusText != null && !rspStr.startsWith("NMC_")) {
					_statusText.append(rspStr + "\n");
					Thread.yield(); // allow graphics repaints
				}
				*/
				parse(rspStr);
			}
		} catch (Exception e) {
			Debug.println("ConfigCert.Exception : " + e.toString());
		}

		Debug.println("ConfigCert.replyHandler: finished, mSuccess=" +
					  mSuccess);

        finish();
    }

    /**
	 * return the value for the given keyword in the reply
	 */
	private void parse(String s) {
		String sName;
		String sValue;
		int iIndex;

		Debug.println("Parse input: " + s);

		if ((iIndex=s.indexOf(":")) != (-1))
		{
			sName = s.substring(0, iIndex).trim();
			sValue = s.substring(iIndex+1).trim();
			Debug.println("Parse input: name=" + sName + " value=" + sValue);
            mWizardInfo.put(sName, sValue);
/*
			if (mCgiResponse == null)
				mCgiResponse = new Hashtable();
			mCgiResponse.put(sName, sValue);
*/
			if (sName.equalsIgnoreCase("NMC_Status"))
			{
				int code = Integer.parseInt(sValue);
				mSuccess = (code == 0);
				Debug.println("Parse input: code=" + code + " mSuccess=" + mSuccess);
			} else if (sName.equalsIgnoreCase("NMC_ERRINFO"))
                mErrorMsg = sValue;
    			Debug.println("ErrorMsg : " + mErrorMsg);
		}

		Debug.println("Parse finished");
    }
}
