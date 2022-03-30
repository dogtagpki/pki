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
package com.netscape.admin.certsrv.task;

import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.CMSServerInfo;
import com.netscape.admin.certsrv.CMSTaskObject;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.keycert.CertSetupWizard;
import com.netscape.admin.certsrv.keycert.CertSetupWizardInfo;
import com.netscape.management.client.IPage;
import com.netscape.management.client.console.ConsoleInfo;

/**
 * Restart the server
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class KeyCert extends CMSTaskObject
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static String PREFIX = "TASKKEYCERT_";

	/*==========================================================
     * constructors
     *==========================================================*/

	public KeyCert() {
		setName(mResource.getString(PREFIX+"KEYCERT_LABEL"));
		setDescription(mResource.getString(PREFIX+"KEYCERT_DESC"));
	}

    /*==========================================================
	 * public methods
     *==========================================================*/
	@Override
    public boolean run(IPage viewInstance) {
        ConsoleInfo console = getConsoleInfo();
        CMSServerInfo serverInfo = (CMSServerInfo)console.get("serverInfo");
        CMSBaseResourceModel model = new CMSBaseResourceModel(console, serverInfo);
        AdminConnection admin = serverInfo.getAdmin();
        CertSetupWizardInfo wizardinfo = new CertSetupWizardInfo(admin, console);
		CertSetupWizard wizard = new CertSetupWizard(model, wizardinfo);
		return true;
	}
}

