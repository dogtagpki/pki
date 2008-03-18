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
 * CRL Extensions Parameter Configuration Dialog
 *
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class OCSPStoresConfigDialog extends CMSBaseConfigDialog
    implements ActionListener
{
    /*==========================================================
     * constructors
     *==========================================================*/
    public OCSPStoresConfigDialog(NameValuePairs nvp,
                                     JFrame parent,
                                     AdminConnection conn,
                                     String dest) {

        super(parent, dest);
        PREFIX = "OCSPSTORECONFIGDIALOG";
        CAHELPINDEX = "configuration-ocsp-edit-crlextensionrule-dbox-help";

        mImplName_token = Constants.PR_OCSPSTORE_IMPL_NAME;
        mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_OCSPSTORESRULE;

        init(nvp,parent,conn,dest);
    }

}    
