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
 * Create or Migrate the Certificate Server
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CMSMigrateCreate extends CGITask
    implements IProductObject
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CMSMIGRATECREATE";

    private static final String CREATE_CGI_NAME = "Tasks/Operation/Create";

	//private boolean mSuccess = false; // status of last executed CGI
	private Hashtable mCgiResponse = null; // holds parsed contents of CGI return
	private String mCgiTask = null; // CGI task to call

	/*==========================================================
     * constructors
     *==========================================================*/
	public CMSMigrateCreate() {
		super();
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void initialize(ConsoleInfo info) {
        Debug.println("CMSMigrateCreate: initialize()");
        _consoleInfo = info;
    }

    public boolean migrate(String serverRoot,
						   String server,
						   String targetDN,
						   boolean flag) {

        Debug.println("CMSMigrateCreate: migrate()");

        return false;
    }

    /**
	 * Starts the server specific creation code, providing the DN for the
	 * target admin group. The method returns true or false depending
	 * on whether it was successful.
	 *
	 * @param  targetDN - the admin group DN where the new instance is to be
	 *                    created.
	 * @return  boolean value indicating whether the process succeeded (true)
	 *          or failed (false).
	 */
	public boolean createNewInstance(String targetDN) {
	    //Debug.println("CMSMigrateCreate: createNewInstance()- "+targetDN);
	    //targetDN: cn=Server Group, cn=cynthiar.mcom.com, ou=mcom.com, o=NetscapeRoot

        JFrame mActiveFrame = UtilConsoleGlobals.getActivatedFrame();
	    boolean status = false; // return value
	    //show dialog
	    CreateInstanceDialog dialog = new CreateInstanceDialog(mActiveFrame);
	                  //  UtilConsoleGlobals.getActivatedFrame());
	    dialog.show();
	    if (dialog.isCancel()) {
	        return status;
	    }

	    //construct the rest of the configuration parameters
        //serverName=cynthiar.mcom.com
        //sieURL=ldap://laiking.mcom.com:389/o=netscapeRoot
        //adminUID=admin
        //adminPWD=admin
        //instanceID=cert-data
        //serverRoot=/u/thomask/s4
        //adminDomain=mcom.com

	    Hashtable configParams = new Hashtable();

	    configParams.put("instanceID",dialog.getInstanceName());

	    String[] entries = LDAPDN.explodeDN(targetDN, false);
	    String DN = entries[entries.length-3] + ", " +
			entries[entries.length-2] + ", " +
			entries[entries.length-1];

		//DN: cn=cynthiar.mcom.com, ou=mcom.com, o=NetscapeRoot

		configParams.put("machineName", getValue(DN, "serverHostName",
								  LDAPConnection.SCOPE_BASE, null));
        configParams.put("serverRoot", getValue(targetDN, "nsconfigroot",
								  LDAPConnection.SCOPE_BASE, null));
        LDAPConnection ldc = _consoleInfo.getLDAPConnection();
		String ssdn = ldc.getAuthenticationDN();
		String[] avas = LDAPDN.explodeDN(ssdn, false);
		String uid = avas[0];
		if (!uid.startsWith("uid")) {
			CMSAdminUtil.showMessageDialog(mActiveFrame,
				mResource, PREFIX, "RESTARTADMINERROR",
				CMSAdminUtil.ERROR_MESSAGE);
			return false;
		}
		configParams.put("adminUID", uid.substring(4,uid.length()));

		configParams.put("adminPWD",ldc.getAuthenticationPassword());
	    String ldapUrl = "ldap://" + ldc.getHost() + ":" +
	                    Integer.toString(ldc.getPort()) + "/" +
	                    (String)_consoleInfo.get("BaseDN");
		configParams.put("sieURL", ldapUrl);

	    String searchDN = entries[entries.length-2];
		configParams.put("adminDomain", searchDN.substring(3,searchDN.length()));

		Debug.println("CMSMigrateCreate: createNewInstance()- "+configParams.toString());

		// set the arguments for the CGI call
		_consoleInfo.put("arguments", configParams);
		_consoleInfo.put(CREATE_CGI_NAME, "cert");
		if (_consoleInfo.get("AdminUsername") == null)
			_consoleInfo.put("AdminUsername", _consoleInfo.getAuthenticationDN());
        Debug.println("AdminUsername = " + _consoleInfo.get("AdminUsername"));

		if (_consoleInfo.get("AdminUserPassword") == null)
			_consoleInfo.put("AdminUserPassword",
							 _consoleInfo.getAuthenticationPassword());
		Debug.println("AdminUserPassword = " + _consoleInfo.get("AdminUserPassword"));

		// call the CGI program
		Debug.println("CMSMigrateCreate: createNewInstance() before run task="+CREATE_CGI_NAME);
		mCgiTask = CREATE_CGI_NAME;

        Cursor cursor = mActiveFrame.getCursor();
        int type = cursor.getType();
        cursor = new Cursor(Cursor.WAIT_CURSOR);
        mActiveFrame.setCursor(cursor);

		try {
			status = super.run(null, CREATE_CGI_NAME);
		} catch (Exception e) {
			Debug.println("Unexpected Error"+e.toString());
			status = false;
		}

		Debug.println("CMSMigrateCreate: createNewInstance() after run status=" +
					  status + " mSuccess=" + mSuccess);

        if (!mSuccess) {
		Debug.println("Show error dialog");
            String errorMsg = getErrorMessage();
            if (errorMsg == null || errorMsg.equals(""))
                CMSAdminUtil.showMessageDialog(mActiveFrame, mResource, PREFIX,
                    "SYSTEMERROR", CMSAdminUtil.ERROR_MESSAGE);
            else
                JOptionPane.showMessageDialog(mActiveFrame, errorMsg,
                  "Error", CMSAdminUtil.ERROR_MESSAGE,
                  CMSAdminUtil.getImage(CMSAdminResources.IMAGE_ERROR_ICON));
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
		if (mCgiResponse != null)
			mCgiResponse.clear();

        try {
			BufferedReader rspStream =
				new BufferedReader(new InputStreamReader(response, "UTF8"));
			String rspStr;

			Debug.println("CMSMigrateCreate: replyHandler() - start");
			while ((rspStr = rspStream.readLine()) != null)
			{
				Debug.println("CMSMigrateCreate: replyHandler() - read [" + rspStr + "]");
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
			Debug.println("MigrateCreate.replyHandler: " + e.toString());
		}

		Debug.println("MigrateCreate.replyHandler: finished, mSuccess=" +
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
			if (mCgiResponse == null)
				mCgiResponse = new Hashtable();
			mCgiResponse.put(sName, sValue);
			if (sName.equalsIgnoreCase("NMC_Status")) {
				int code = Integer.parseInt(sValue);
				mSuccess = (code == 0);
				Debug.println("Parse input: code=" + code + " mSuccess=" + mSuccess);
			} else if (sName.equalsIgnoreCase("NMC_ERRINFO")) {
                mErrorMsg = sValue;
            }
		}

		Debug.println("Parse finished");
    }

    /**
     * Get one value for one specified attribute from the given DN.
	 * If there is more than 1 entry which matches the given criteria, the
	 * first one will be used.
     *
     * @param  DN     DN of the entry with the specified attributes
     * @param  attr   Attribute to get the value of
	 * @param  scope  LDAPConnection SCOPE_BASE SCOPE_ONE SCOPE_SUB
	 * @param  filter LDAP search filter; if null, default is objectclass=*
     * @return        The string value of the attribute; multi-valued
	 *                attributes are returned as 1 value, space delimited
	 *                (flattened)
     **/
    protected String getValue(String DN, String attr, int scope,
							  String filter) {
		String[] attrs = { attr };
		String[] values = getValues(DN, attrs, scope, filter);
		if (values != null)
			return values[0];

		return null;
	}

    /**
     * Get the values for several specified attributes from the given DN.
	 * If there is more than 1 entry which matches the given criteria, the
	 * first one will be used.
     *
     * @param  DN     DN of the entry with the specified attributes
     * @param  attrs  Array of attributes to get the values of
	 * @param  scope  LDAPConnection SCOPE_BASE SCOPE_ONE SCOPE_SUB
	 * @param  filter LDAP search filter; if null, default is objectclass=*
     * @return        An array of string values for each attribute; multi-valued
	 *                attributes are returned as 1 value, space delimited
	 *                (flattened)
     **/
    protected String[] getValues(String DN, String[] attrs, int scope,
								 String filter) {
		String[] values = null;
		LDAPSearchResults results = null;
		if (filter == null)
			filter = "(objectclass=*)";

		try {
			LDAPConnection ldc = _consoleInfo.getLDAPConnection();
			if (ldc != null)
			{
				results = ldc.search(DN, scope, filter, attrs, false);
			}
		} catch (LDAPException e) {
			Debug.println("error MigrateCreate.getValues: LDAP read failed " +
						  "for DN=" + DN + " attributes " + attrs);
			Debug.println("error MigrateCreate.getValues: LDAP Exception:" +
						  e);
		}

		if (results != null && results.hasMoreElements()) {
			values = new String[attrs.length];
			LDAPEntry entry = (LDAPEntry)results.nextElement();
			for (int ii = 0; entry != null && ii < attrs.length; ++ii) {
				values[ii] = LDAPUtil.flatting(entry.getAttribute(attrs[ii]));
			}
		} else {
			Debug.println("error MigrateCreate.getValues: LDAP read failed " +
						  "for DN=" + DN + " attributes=" + attrs);
		}

		return values;
    }

}
