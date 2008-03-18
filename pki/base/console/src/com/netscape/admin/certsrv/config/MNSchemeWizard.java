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
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.management.client.util.*;

/**
 * Wizard for reconfiguring the Recovery MN Scheme
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class MNSchemeWizard extends WizardWidget {

    /*==========================================================
     * variables
     *==========================================================*/


	/*==========================================================
     * constructors
     *==========================================================*/
    public MNSchemeWizard(JFrame parent, MNSchemeWizardInfo info) {
        super(parent);
        setWizardInfo(info);
        //add page here
        addPage(new WMNSelection());
        addPage(new WMNOldAgent());
        addPage(new WMNNewAgent());
        addPage(new WMNResultPage());
        show();
    }

    /*==========================================================
	 * protected methods
     *==========================================================*/
    protected void callHelp() {
        if (mCurrent instanceof IWizardPanel) {
			((IWizardPanel)mCurrent).callHelp();
		}
    }

}

