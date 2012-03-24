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
 * Jobs Plugin Selection Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class JobsPluginSelectionDialog extends PluginSelectionDialog
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "JOBSSELECTIONDIALOG";
    private static final String HELPINDEX = 
      "jobsscheduler-certsrv-add-jobrule-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public JobsPluginSelectionDialog(
			JFrame parent,
			AdminConnection conn, 
			String dest,
			CMSPluginInstanceTab pluginType) 
	{
        super(PREFIX, parent,conn, dest, pluginType);
        mScope         = ScopeDef.SC_JOBS_IMPLS;
        mInstanceScope = ScopeDef.SC_JOBS_INSTANCE;
        mImageName     = CMSAdminResources.IMAGE_RULE_PLUGIN;
        if (dest.equals(DestDef.DEST_JOBS_ADMIN))
            mHelpToken = HELPINDEX;

        setDisplay();
    }

}
