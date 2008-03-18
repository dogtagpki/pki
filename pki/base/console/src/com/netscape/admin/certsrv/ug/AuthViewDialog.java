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
 * Authentication Parameter View Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.ug
 */
public class AuthViewDialog extends AuthBaseDialog
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "AUTHVIEWDIALOG";
    private static final String HELPINDEX = 
      "authentication-certsrv-view-authrule-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public AuthViewDialog(CMSBaseResourceModel model) {
        super(model.getFrame(), Constants.VIEW, PREFIX);
        mConn = model.getServerInfo().getAdmin();
        mDataModel = new ViewTableModel();
        setDisplay();
    }

    public void actionPerformed(ActionEvent evt) {
        super.actionPerformed(evt);
        if (evt.getSource().equals(mHelp))
            CMSAdminUtil.help(HELPINDEX);
    }
}
