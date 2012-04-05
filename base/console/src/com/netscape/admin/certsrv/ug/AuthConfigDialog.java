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
package com.netscape.admin.certsrv.ug;

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;


/**
 * Auth Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class AuthConfigDialog extends CMSBaseConfigDialog
{
    /*==========================================================
     * constructors
     *==========================================================*/

	public AuthConfigDialog(NameValuePairs nvp,
		JFrame parent,
		AdminConnection conn,
		String dest) {

		super(parent,dest);

		PREFIX = "AUTHCONFIGDIALOG";
		RAHELPINDEX = "authentication-certsrv-edit-authrule-dbox-help";
		KRAHELPINDEX = "authentication-certsrv-edit-authrule-dbox-help";
		CAHELPINDEX = "authentication-certsrv-edit-authrule-dbox-help";
		mImplName_token = Constants.PR_AUTH_IMPL_NAME;
		mImplType = Constants.PR_EXT_PLUGIN_IMPLTYPE_AUTH;
        mHelpToken = "configuration-authentication";
		init (nvp,parent,conn,dest);
	}

	public String getDefaultInstanceName(String implName)
	{
		Debug.println("Getting DefaultInstanceName for "+implName);
		String instanceName = "";
		if (implName.equals("UidPwdDirAuth")) {
			instanceName = "UserDirEnrollment";
		}
		else if (implName.equals("UidPwdPinDirAuth")) {
			instanceName = "PinDirEnrollment";
		}
		else if (implName.equals("UdnPwdDirAuth")) {
			instanceName = "UserDnEnrollment";
		}
		else if (implName.equals("NISAuth")) {
			instanceName = "NISAuth";
		}
		else if (implName.equals("PortalEnroll")) {
			instanceName = "PortalEnrollment";
		}

		Debug.println("Returning instance name "+instanceName);
		return instanceName;

	}


}
