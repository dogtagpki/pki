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
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Publishing Rule Plugin Selection Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class RulePluginSelectionDialog extends PluginSelectionDialog
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "RULESELECTIONDIALOG";
    private static final String CAHELPINDEX = 
      "configuration-ca-add-rulerule-dbox-help";
    private static final String RAHELPINDEX =
      "configuration-ra-add-rulerule-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public RulePluginSelectionDialog(
			JFrame parent,
			AdminConnection conn, 
			String dest,
			CMSPluginInstanceTab pluginType) 
	{
        super(PREFIX, parent,conn, dest, pluginType);
        mScope = ScopeDef.SC_RULE_IMPLS;
        mInstanceScope = ScopeDef.SC_RULE_RULES;
        mImageName = CMSAdminResources.IMAGE_RULE_PLUGIN;
        if (dest.equals(DestDef.DEST_RA_RULE_ADMIN))
            mHelpToken = RAHELPINDEX;
        else
            mHelpToken = CAHELPINDEX;
        setDisplay();
    }

    /*==========================================================
     * EVENT HANDLER METHODS
     *==========================================================*/


}
