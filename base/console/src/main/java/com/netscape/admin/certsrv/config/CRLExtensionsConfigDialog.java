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

import javax.swing.JFrame;

import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;

/**
 * CRL Extensions Parameter Configuration Dialog
 *
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CRLExtensionsConfigDialog extends CMSBaseConfigDialog
{
    /*==========================================================
     * constructors
     *==========================================================*/
    public CRLExtensionsConfigDialog(NameValuePairs nvp,
                                     JFrame parent,
                                     AdminConnection conn,
                                     String dest) {

        super(parent, dest);
        PREFIX = "CRLEXTCONFIGDIALOG";
        CAHELPINDEX = "configuration-ca-edit-crlextensionrule-dbox-help";

        mImplName_token = Constants.PR_CRLEXT_IMPL_NAME;
        mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_CRLEXTSRULE;

        init(nvp,parent,conn,dest);
    }

    public CRLExtensionsConfigDialog(NameValuePairs nvp,
                                     JFrame parent,
                                     AdminConnection conn,
                                     String dest,
                                     String id) {

        super(parent, dest);
        PREFIX = "CRLEXTCONFIGDIALOG";
        CAHELPINDEX = "configuration-ca-edit-crlextensionrule-dbox-help";

        mImplName_token = Constants.PR_CRLEXT_IMPL_NAME;
        mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_CRLEXTSRULE;

        init(nvp,parent,conn,dest,id);
    }

}
