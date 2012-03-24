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
 * Start daemon to do the certificate server configuration.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSStartDaemon extends CGITask {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CMSSTARTDAEMON";
    
    public static final String START_DAEMON_CGI = "Tasks/Operation/start-daemon";
    
	private boolean mSuccess = false; // status of last executed CGI
	private Hashtable mCgiResponse = null; // holds parsed contents of CGI return
	private String mCgiTask = null; // CGI task to call
	
	/*==========================================================
     * constructors
     *==========================================================*/
	public CMSStartDaemon() {
		super();
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void initialize(ConsoleInfo info) {
        Debug.println("CMSStartDaemon: initialize()");
        _consoleInfo = info;
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
	public boolean runDaemon(Hashtable configParams) {
        String response = null;	    
/*
        LDAPConnection ldc = _consoleInfo.getLDAPConnection();
        String ssdn = ldc.getAuthenticationDN();
        String[] avas = LDAPDN.explodeDN(ssdn, false);
        String uid = avas[0];
        configParams.put("adminUID", uid.substring(4,uid.length()));

        configParams.put("adminPWD",ldc.getAuthenticationPassword());

        _consoleInfo.put(START_DAEMON_CGI, "cert-bcsnpk");
*/
        _consoleInfo.put("arguments", configParams);

        if (_consoleInfo.get("AdminUsername") == null)
            _consoleInfo.put("AdminUsername", _consoleInfo.getAuthenticationDN());
        Debug.println("AdminUsername = " + _consoleInfo.get("AdminUsername"));

        if (_consoleInfo.get("AdminUserPassword") == null)
            _consoleInfo.put("AdminUserPassword",
                             _consoleInfo.getAuthenticationPassword());
        Debug.println("AdminUserPassword = " + _consoleInfo.get("AdminUserPassword")); 

        Debug.println("Current DN = "+_consoleInfo.getCurrentDN());
	    boolean status = false; // return value

		try {
			status = super.run(null, START_DAEMON_CGI);
		} catch (Exception e) {
			Debug.println("Unexpected Error"+e.toString());
			status = false;
		}
		Debug.println("CMSStartDaemon: startDaemon() after run status=" +
					  status + " mSuccess=" + mSuccess);
again:		
        if (!mSuccess) {
            response = (String) mCgiResponse.get("NMC_ERRINFO");
            if ((response != null) && response.equalsIgnoreCase("daemon found lock file")) {
                int result = CMSAdminUtil.showConfirmDialog(mResource, "CMSSTARTDAEMON"/*PREFIX*/, 
                        "LOCKDELETECONFIRM", CMSAdminUtil.WARNING_MESSAGE);
                if (result == CMSAdminUtil.OK_OPTION) {
    		        Debug.println("User wants to delete lock file.");
                    configParams.put("IGNORE", "TRUE");
        			status = super.run(null, START_DAEMON_CGI);
        			break again;
		        }
		        else
    		        Debug.println("User doesn't want to delete lock file.");
		    }
            else {
		        Debug.println("Show error dialog");
                CMSAdminUtil.showMessageDialog(UtilConsoleGlobals.getActivatedFrame(), mResource, PREFIX,
                    "SYSTEMERROR", CMSAdminUtil.ERROR_MESSAGE);
            }
        }
        
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

			Debug.println("CMSStartDaemon: replyHandler() - start");
			while ((rspStr = rspStream.readLine()) != null)
			{
				Debug.println("CMSStartDaemon: replyHandler() - read [" + rspStr + "]");
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
			Debug.println("StartDaemon.replyHandler: " + e.toString());
		}
		
		Debug.println("StartDaemon.replyHandler: finished, mSuccess=" +
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
			if (sName.equalsIgnoreCase("NMC_Status"))
			{
				int code = Integer.parseInt(sValue);
				mSuccess = (code == 0);
				Debug.println("Parse input: code=" + code + " mSuccess=" + mSuccess);
			}
		}

		Debug.println("Parse finished");
    }
    
    /**
	 * return the value for the response
	 */
	public Hashtable getResponse() {
		return mCgiResponse; 
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
