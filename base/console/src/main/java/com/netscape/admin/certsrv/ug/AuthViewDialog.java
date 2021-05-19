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
import java.awt.event.*;
import com.netscape.certsrv.common.*;

/**
 * Authentication Parameter View Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
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

    @Override
    public void actionPerformed(ActionEvent evt) {
        super.actionPerformed(evt);
        if (evt.getSource().equals(mHelp))
            CMSAdminUtil.help(HELPINDEX);
    }
}
