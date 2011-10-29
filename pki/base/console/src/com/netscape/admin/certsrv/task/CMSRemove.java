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
import com.netscape.management.client.console.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import netscape.ldap.*;

/**
 * Remove the server
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CMSRemove extends CGITask
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "TASKREMOVE";
    public static final String REMOVE_TASK_CGI = "Tasks/Operation/remove";
    private Hashtable mCgiResponse = null;
    private String mCgiTask = null;

	/*==========================================================
     * constructors
     *==========================================================*/

	public CMSRemove() {
        super();
		setName(mResource.getString(PREFIX+"_REMOVE_LABEL"));
		setDescription(mResource.getString(PREFIX+"_REMOVE_DESC"));
	}

    public void initialize(ConsoleInfo info) {
        Debug.println("CMSRemove: initialize()");
        _consoleInfo = info;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
	public boolean run(IPage viewInstance)
	{
        Debug.println("CMSRemove: run()");
        boolean status = false; // return value
        Hashtable configParams = new Hashtable();
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
                    "ERROR CMSRemove: LDAP read failed: " +
                    configDN);
        }
        _consoleInfo.put("arguments", configParams);

		String authdn = _consoleInfo.getAuthenticationDN();

        if (_consoleInfo.get("AdminUsername") == null)
            _consoleInfo.put("AdminUsername", authdn);

        if (!authdn.startsWith("uid")) {
			JFrame mActiveFrame = UtilConsoleGlobals.getActivatedFrame();
			CMSAdminUtil.showMessageDialog(mActiveFrame,
					mResource, PREFIX, "RESTARTADMINERROR",
					CMSAdminUtil.ERROR_MESSAGE);
			return false;
		}

        Debug.println("AdminUsername = " + _consoleInfo.get("AdminUsername"));

        if (_consoleInfo.get("AdminUserPassword") == null)
            _consoleInfo.put("AdminUserPassword",
                             _consoleInfo.getAuthenticationPassword());
        Debug.println("AdminUserPassword = " + _consoleInfo.get("AdminUserPassword"));
        // call the CGI program
        Debug.println("CMSRemove: remove() before run task="+REMOVE_TASK_CGI);
        try {
            status = super.run(null, REMOVE_TASK_CGI);
        } catch (Exception e) {
            Debug.println("Unexpected Error"+e.toString());
            status = false;
        }
        Debug.println("CMSRemove: remove() after run status="+status);

        String title = mResource.getString("REMOVERESULTDIALOG_TITLE");

        if (!status) {
            Debug.println("Show error dialog");
            // if no error message from the server, then just show the generic
            // error message.
            if (mErrorMsg.equals(""))
                CMSAdminUtil.showMessageDialog(
                  UtilConsoleGlobals.getActivatedFrame(),
                  mResource, PREFIX, "SYSTEMERROR", CMSAdminUtil.ERROR_MESSAGE);
            else {
                String errorMsg =
                  mResource.getString("REMOVERESULTDIALOG_FAILED_TEXT")+mErrorMsg;
                Icon icon = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_ERROR_ICON);
                JOptionPane.showMessageDialog(UtilConsoleGlobals.getActivatedFrame(),
                  errorMsg, title, JOptionPane.ERROR_MESSAGE, icon);
            }
        } else {
            Debug.println("Successful operation");
            String msg = mResource.getString("REMOVERESULTDIALOG_SUCCESS_TEXT");
            Icon icon = CMSAdminUtil.getImage(CMSAdminResources.IMAGE_INFO_ICON);
            JOptionPane.showMessageDialog(UtilConsoleGlobals.getActivatedFrame(),
              msg, title, JOptionPane.INFORMATION_MESSAGE, icon);
        }
        return status;
    }
}

