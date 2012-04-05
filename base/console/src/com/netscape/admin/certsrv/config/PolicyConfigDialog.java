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
package com.netscape.admin.certsrv.config;

import com.netscape.admin.certsrv.*;
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
 * Policy Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class PolicyConfigDialog extends CMSBaseConfigDialog
    implements ActionListener
{

    /*==========================================================
     * constructors
     *==========================================================*/
    public PolicyConfigDialog(NameValuePairs nvp,
				JFrame parent,
				AdminConnection conn,
				String dest) {

        super(parent, dest);

		PREFIX = "POLICYCONFIGDIALOG";
    	RAHELPINDEX = "configuration-ra-edit-policyrule-dbox-help";
    	KRAHELPINDEX = "configuration-kra-edit-policyrule-dbox-help";
    	CAHELPINDEX = "configuration-ca-edit-policyrule-dbox-help";
		mImplName_token = Constants.PR_POLICY_IMPL_NAME;
		mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_POLICY;

		init(nvp,parent,conn,dest);
    }

}
