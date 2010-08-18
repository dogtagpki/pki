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

import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

/**
 * Represents the task entry on the task Tab.
 *
 * @author Thomas Kwan
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.management.client.TaskObject
 */
public class CMSTaskObject extends TaskObject
{
    /*==========================================================
     * variables
     *==========================================================*/
	private CMSServerInfo mServerInfo = null;       // server info
    protected ResourceBundle mResource;

	/*==========================================================
     * constructors
     *==========================================================*/
	public CMSTaskObject() {
		super();
		mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
	}

	public CMSTaskObject(CMSServerInfo serverInfo, String name, 
			ConsoleInfo info) {
		super(name, info);
		mServerInfo = serverInfo;
		mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
	public void setServerInfo(CMSServerInfo i) {
		mServerInfo = i;
	}

	public CMSServerInfo getServerInfo() {
		return mServerInfo;
	}
	
}
