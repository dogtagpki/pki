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

import java.util.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.management.client.*;
import com.netscape.management.client.console.*;
import com.netscape.admin.certsrv.keycert.*;

/**
 * Restart the server
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
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

