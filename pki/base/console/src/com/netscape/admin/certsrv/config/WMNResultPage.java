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

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Result page for the Recovery MN Scheme
 *
 * @author Christine Ho
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
class WMNResultPage extends WizardBasePanel
    implements IWizardPanel
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANELNAME = "WMNRESULTPAGE";

    private static final String HELPINDEX = 
      "configuration-kra-wizard-newagentpwd-keyscheme-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    WMNResultPage() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return true;
    }

    /*==========================================================
     * public methods
     *==========================================================*/
    public boolean initializePanel(WizardInfo info) {
        return true;
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    //initialize the panel
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = makeJLabel("DESC");
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        add(label3,gbc);

        super.init();
    }
}

