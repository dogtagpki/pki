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

import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardWidget;

/**
 * Wizard for reconfiguring the Recovery MN Scheme
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
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
        setVisible(true);
    }

    /*==========================================================
	 * protected methods
     *==========================================================*/
    @Override
    protected void callHelp() {
        if (mCurrent instanceof IWizardPanel) {
			((IWizardPanel)mCurrent).callHelp();
		}
    }

}

