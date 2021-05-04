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

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.util.Hashtable;

import com.netscape.admin.certsrv.CMSAdmin;
import com.netscape.management.client.IPage;
import com.netscape.management.client.comm.HttpManager;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;

/**
 * Retrieve the status of the server
 *
 * @author Ross Fubini
 * @version $Revision$, $Date$
 */
public class CMSStatus extends CGITask
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/
    // private static final String PREFIX = "TASKSTATUS";
    public static final String STATUS_TASK_CGI = "Tasks/Operation/status";

	/*==========================================================
     * constructors
     *==========================================================*/

	public CMSStatus() {
        super();
/*
		setName(mResource.getString(PREFIX+"_STATUS_LABEL"));
		setDescription(mResource.getString(PREFIX+"_STATUS_DESC"));
*/
	}

    public void initialize(ConsoleInfo info) {
        Debug.println("CMSStatus: initialize()");
        _consoleInfo = info;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
	public boolean run(IPage viewInstance)
	{
        Debug.println("CMSStatus: run()");
        boolean status = false; // return value

        Hashtable<String, Object> configParams = new Hashtable<>();
        configParams.put("serverRoot",_consoleInfo.get("serverRoot"));
        String servid = (String)_consoleInfo.get("servid");
        int index = servid.indexOf("-");
        if (index != -1) {
            servid = servid.substring(index+1);
        }
        configParams.put("instanceID", servid);

		// get the CMS instance host and port
		servid = (String)_consoleInfo.get("servid");
        String configDN = _consoleInfo.getCurrentDN();

        try {
            LDAPConnection ldc = _consoleInfo.getLDAPConnection();
            if (ldc == null) {
                ldc = new LDAPConnection();
            }
            if (ldc.isConnected() == false) {
                ldc.connect(_consoleInfo.getHost(), _consoleInfo.getPort(),
                        _consoleInfo.getAuthenticationDN(),
                        _consoleInfo.getAuthenticationPassword());
            }
            LDAPEntry entry = ldc.read(configDN);
            String cmsHost = LDAPUtil.flatting(
                    entry.getAttribute("serverHostName",
                    LDAPUtil.getLDAPAttributeLocale()));
            String cmsPort = LDAPUtil.flatting(
                    entry.getAttribute("nsServerPort",
                    LDAPUtil.getLDAPAttributeLocale()));

			Debug.println("host:" + cmsHost+" port:"+cmsPort);
			configParams.put("cmsHost", cmsHost);
			configParams.put("cmsPort", cmsPort);
        }
        catch (LDAPException e) {
            Debug.println(
                    "ERROR CMSStatus: LDAP read failed: " +
                    configDN);
        }
        _consoleInfo.put("arguments", configParams);

        if (_consoleInfo.get("AdminUsername") == null)
	  _consoleInfo.put("AdminUsername", _consoleInfo.getAuthenticationDN()
);
        Debug.println("AdminUsername = " + _consoleInfo.get("AdminUsername"));

        if (_consoleInfo.get("AdminUserPassword") == null)
            _consoleInfo.put("AdminUserPassword",
                             _consoleInfo.getAuthenticationPassword());
        Debug.println("AdminUserPassword = " + _consoleInfo.get("AdminUserPassword"));

        // call the CGI program
        Debug.println("CMSStatus: status() before run task="+STATUS_TASK_CGI);
        try {
	    status = getStatusWithFallback(null, STATUS_TASK_CGI);
        } catch (Exception e) {
	  Debug.println("Unexpected Error"+e.toString());
	  status = false;
        }
        Debug.println("CMSStatus: status() after run status="+status);

        if (!status) {
	  Debug.println("Status task returned false");
	} else {
	  Debug.println("Successful operation");
        }
	return status;
	}


  	/**
	 * Send an http request to the server.
	 * if the admin serever is down do
	 * Return true if we're sure it
	 * succeeded, otherwise false.
	 *
	 * @param viewInstance The calling page
	 * @param cmd Command to execute
	 */
  boolean getStatusWithFallback(IPage viewInstance, String cmd) {
    // get the admin URL location first
    mAdminURL = _consoleInfo.getAdminURL();
    if ( mAdminURL == null ) {
      Debug.println( "Could not get adminURL for " + getDN() );
      return false;
    }

    // Allow specifying e.g. "slapd-install" for instance
    String instance = (String)_consoleInfo.get( cmd );

    if ( instance == null )
      instance = (String)_consoleInfo.get( "ServerInstance" );
    String fullCmd = mAdminURL + instance + "/" + cmd;

    HttpManager h = new HttpManager();
    // tell the http manager to use UTF8 encoding
    HttpManager.setSendUTF8(true);

    try {
      mSuccess = false;
      mFinished = false;

      // _consoleInfo.get("arguments") is a hashtable of key/value pairs
      // to use as the arguments to the CGI
      Hashtable<String, Object> args = (Hashtable<String, Object>)_consoleInfo.get("arguments");
      ByteArrayInputStream data = null;
      if (args != null && !args.isEmpty())
	data = encode(args);
      Debug.println( "Posting " + fullCmd );
      // tell the http manager to notify us immediately of replies
      // if we're using async mode
      int flags = 0;
      if (data == null)
	h.post(new URL(fullCmd), this, null, null, 0,
	       flags);
      else
	h.post(new URL(fullCmd), this, null, data, data.available(),
	       flags);
      awaitSuccess();
      Debug.println( "Command executed: " + fullCmd );
    } catch (Exception e) {
      if ( e instanceof java.net.ConnectException ) {
	Debug.println( "Admin server failed to status task" );
            CMSAdmin cmsAdmin = (CMSAdmin)(_consoleInfo.get("CMSAdmin"));
	    mSuccess = cmsAdmin.getStatusFromAgentPort();
      }
      Debug.println( "Falling back to get status by connecting to the server");

    }
    return mSuccess;
  }
}

