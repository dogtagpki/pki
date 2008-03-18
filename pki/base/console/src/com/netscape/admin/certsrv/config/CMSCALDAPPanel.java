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

import com.netscape.management.client.util.*;

/**
 * LDAP server setting tab
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSCALDAPPanel extends CMSBaseLDAPPanel {

    private static String PANEL_NAME = "CALDAPSETTING";
    private static final String HELPINDEX = 
      "configuration-ca-ldappublish-destination-help";

    public CMSCALDAPPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mHelpToken = HELPINDEX;
    }

    public void init() {
        super.init();
        refresh();
    }
}

