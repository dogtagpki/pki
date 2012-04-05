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
 * CRL Extensions Plugin Selection Dialog
 *
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CRLExtensionsPluginSelectionDialog extends PluginSelectionDialog
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "CRLEXTSELECTIONDIALOG";
    private static final String CAHELPINDEX =
      "configuration-ca-add-crlextensionrule-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CRLExtensionsPluginSelectionDialog(
            JFrame parent,
            AdminConnection conn,
            String dest,
            CMSPluginInstanceTab pluginType)
	{
        super(PREFIX, parent,conn, dest, pluginType);
//        mScope = ScopeDef.SC_RULE_IMPLS;
        mInstanceScope = ScopeDef.SC_CRLEXTS_RULES;
        mImageName = CMSAdminResources.IMAGE_RULE_PLUGIN;
        mHelpToken = CAHELPINDEX;
        setDisplay();
    }

    /*==========================================================
     * EVENT HANDLER METHODS
     *==========================================================*/

}
