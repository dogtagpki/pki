/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.security;

import java.awt.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.client.util.ModalDialogUtil;

/**
 * Certificate Migrate wizard.
 * 
 * Certificate Migrate wizard will guide user through the process
 * to Migrate certificate.
 *
 * for design detail see: http://lupine.mcom.com/console/4.5/security/import.htm
 * 
 * 
 */
public class CertMigrateWizard  {

    Wizard wizardDialog;
    IWizardSequenceManager sequenceManager = new WizardSequenceManager();
    IDataCollectionModel dataCollectionModel = new WizardDataCollectionModel();


    /**
     * Create a instance of the certifificate migration wizard.
     *
     * Guide user for migrating a key/cert db from an old server instance.
     *
     * @param parent component from where this wizard was lunched
     * @param consoleInfo information required for this wizard to contact admin server inorder to generate key pair and CSR
     * @param sie server instance name (ie. admin-serve-HOSTNAME)
     *
     */
    public CertMigrateWizard(Component parent, 
			     ConsoleInfo consoleInfo, 
			     String sie) {

        if (parent == null) {
            parent = UtilConsoleGlobals.getActivatedFrame();
        } 

	wizardDialog = new Wizard((parent instanceof Frame)?(Frame)parent:null,
				  KeyCertUtility.getResourceSet().getString("CertMigrateWizard", "title"),
				  true, 
				  sequenceManager,
				  dataCollectionModel);
    
	dataCollectionModel.setValue("sie", sie);

        try {
            wizardDialog.addPage("CertMigrateSourcePage", new CertMigrateSourcePage(consoleInfo));
            wizardDialog.addPage("CertMigrateAliasSelectionPage", new CertMigrateAliasSelectionPage(consoleInfo));
	    wizardDialog.addPage("CertMigrateConfirmPage", new CertMigrateConfirmPage(consoleInfo));
        }catch (Exception e) {
	    SecurityUtil.printException("CertMigrateWizard::CertMigrateWizard(...)",e);
        }

        wizardDialog.setSize(500, 350);

        if (parent != null) {
            ModalDialogUtil.setDialogLocation(wizardDialog,parent);
        }
    }


    /**
     * Show or hide certificate request wizard
     *
     * @param visible if true wizard will be lunched
     */
    public void setVisible(boolean visible) {
        wizardDialog.setVisible(visible);
    }

    /*public static void main(String arg[]) {
        try {
            UIManager.setLookAndFeel(new SuiLookAndFeel());
        } catch (Exception e) {}
	Debug.setTrace(true);

        JFrame f = new JFrame();

        ConsoleInfo consoleInfo = new ConsoleInfo();
        consoleInfo.setAuthenticationDN("admin");
        consoleInfo.setAuthenticationPassword("admin");
        consoleInfo.setAdminURL("http://buddha:8081/");
	consoleInfo.setPort(8081);
	consoleInfo.setHost("buddha");

        CertMigrateWizard w = new CertMigrateWizard(f, consoleInfo, "ADMIN-SERV-BUDDHA");
        w.setVisible(true);
    }*/
}
