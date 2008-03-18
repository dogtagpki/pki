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
package com.netscape.admin.certsrv;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.text.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;

/**
 * Certificate server information. Store all relevant
 * information that allows this client to connect to
 * the certificate server.
 *
 * @author Jack Pan-Chen
 * @author Thomas Kwan
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSServerInfo implements IConnectionListener {
    
    /*==========================================================
     * variables
     *==========================================================*/    
    private static final String PREFIX = "SERVER";
	private AdminConnection mAdmin = null;     // srever entry point
	private String mHost = null;                // server host
	private int mPort;                          // server port
	private String mServerId = null;            // server id
    private String mServerRoot = null;
	private String mServerVersion = null;       // server version
	private String mUserid = null;              // user id
	private String mInstallDate = null;         // server install date
	private String mPassword = null;            // user password
	private String mPath = null; 
	private Vector mSubsystem = new Vector();

	/*==========================================================
     * constructors
     *==========================================================*/
	public CMSServerInfo(String host, int port, String userid, String password,
	                     String serverid, String installDate, String version,
      String serverRoot, String path) 
	    throws EAdminException 
	{

		mHost = host;
		mPort = port;
		mUserid = userid;
		mPassword = password;
		mServerId = serverid;
        mServerVersion = version;
        mInstallDate = installDate;
        mServerRoot = serverRoot;
		mPath = path;
        
        Debug.println("CMSServerInfo: host "+mHost+" port "+mPort+
          " userid "+mUserid+" serverRoot "+mServerRoot+" serverid "+mServerId);
        mAdmin = new AdminConnection(
	                new BasicAuthenticator(mUserid, mPassword), 
	                new SSLConnectionFactory(SSLConnectionFactory.JSS_CONNECTION),
	                true /* KeepAlive */, mHost, mPort, mPath);
		mAdmin.setConnectionListener(this);	
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
     
    public void restartCallback() {
        JFrame frame = UtilConsoleGlobals.getActivatedFrame();
        if (frame != null) {
            ResourceBundle bundle =
              ResourceBundle.getBundle(CMSAdminResources.class.getName());
            CMSAdminUtil.showMessageDialog(frame, bundle, PREFIX, "RESTART",
              CMSAdminUtil.WARNING_MESSAGE);
        }
    }

    public void ping() throws EAdminException {
		
		// Need to do authentication here
		NameValuePairs config = new NameValuePairs();
		config.add(Constants.PR_PING,"");
		
		NameValuePairs response;
		
		response = mAdmin.read(DestDef.DEST_AUTH_ADMIN,
		            ScopeDef.SC_AUTH,
		            Constants.RS_ID_CONFIG,
		            config);
		
		if (!response.getValue(Constants.PR_PING).equalsIgnoreCase(Constants.TRUE)) {
            Debug.println("Ping failed -> Server off");
		    throw new EAdminException("PING_FAILED",false);
	    }
    }
    
    public void authenticate() throws EAdminException {
        mAdmin.auth(DestDef.DEST_AUTH_ADMIN, ScopeDef.SC_AUTH);
    }

    public String getAuthType() throws EAdminException {
        return mAdmin.authType(DestDef.DEST_AUTH_ADMIN, ScopeDef.SC_AUTHTYPE);
    }

	public AdminConnection getAdmin() {
		return mAdmin;
	}

	public String getHost() {
		return mHost;
	}

	public int getPort() {
		return mPort;
	}
	
	public String getUserId() {
	    return mUserid;    
	}
	
	public String getServerId() {
	    return mServerId;    
	}

	public String getServerRoot() {
	    return mServerRoot;    
	}

    public String getServerVersion() {
        return mServerVersion;
    }
    
    public String getInstallDate() {
        return mInstallDate;    
    }
    
	public Object clone() {
		try {
			return new CMSServerInfo(mHost, mPort, mUserid, mPassword,
			                mServerId, mServerVersion, mInstallDate, mServerRoot, mPath);
		} catch (EAdminException e) {
			return null;
		}
	}
	
	public Vector getInstalledSubsystems() {
        return mSubsystem;
	}
	
	public void setInstalledSubsystems(Vector subsystem) {
	    mSubsystem = subsystem;
	}
	
}
