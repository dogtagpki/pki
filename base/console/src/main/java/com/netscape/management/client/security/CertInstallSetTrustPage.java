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

import com.netscape.management.client.components.Wizard;
import com.netscape.management.client.components.*;
import java.awt.*;
import java.net.*;
import java.util.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.nmclf.*;

class CertInstallSetTrustPage extends WizardPage implements SuiConstants {

    JCheckBox clientTrust, serverTrust;
    Hashtable pwdCache = new Hashtable();
    
    public boolean nextInvoked() {
	boolean canProceed = false;
	//install cert here
    Wizard wizard = (Wizard) SwingUtilities.getAncestorOfClass(Wizard.class, this);
	try {
	    if (wizard != null) {
            wizard.setBusyCursor(true);
	    }

	    Hashtable args = new Hashtable();
	    args.put("formop", "INSTALL_CERT");

	    //if installmethod is any none null value
	    //then the cgi will attempt to add cert.
	    args.put("installmethod", "1");
	    IDataCollectionModel dataCollectionModel = getDataModel();

	    args.put("sie"      , dataCollectionModel.getValue("sie"));
	    args.put("tokenname", dataCollectionModel.getValue("tokenname"));
	    args.put("dercert"  , dataCollectionModel.getValue("dercert"));
	    args.put("certtype" , dataCollectionModel.getValue("certtype"));
	    args.put("certname" , dataCollectionModel.getValue("certname"));
	    for (Enumeration e=pwdCache.keys(); e.hasMoreElements();) {
	        Object tokenPwd = e.nextElement();
	        args.put(tokenPwd, pwdCache.get(tokenPwd));
	    }

	    int t = (clientTrust.isSelected()?EditTrustDialog.TRUSTED_CLIENT_CA:0) |
	             (serverTrust.isSelected()?EditTrustDialog.TRUSTED_CA:0);
	    args.put("trust_flag", Integer.toString(t));
	    //static int TRUSTED_CA       = 16;
	    //static int TRUSTED_CLIENT_CA  = 128;

	    ConsoleInfo consoleInfo = (ConsoleInfo)(dataCollectionModel.getValue("consoleInfo"));

	    AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
						  "admin-serv/tasks/configuration/SecurityOp"),
					  consoleInfo.getAuthenticationDN(),
					  consoleInfo.getAuthenticationPassword());

	    SecurityUtil.execWithPwdInput(admTask, args, pwdCache);

	    admTask.setArguments(args);

	    admTask.exec();
	    Debug.println(admTask.getResultString().toString());

	    if (!SecurityUtil.showError(admTask)) {
		dataCollectionModel.setValue("certlist", new CertificateList(admTask.getResultString().toString()));
		canProceed = true;
	    } 
	} catch (Exception e) {
	    SecurityUtil.printException("CertInstallSetTrustPage::nextInvoked()",e);
	}
	finally {
	    if (wizard != null) {
            wizard.setBusyCursor(false);
        }
    }          

	return canProceed;
    }

    public void helpInvoked() {
	KeyCertUtility.getHelp().contextHelp("CertInstallSetTrustPage", "help");
    }

    public CertInstallSetTrustPage() {
        super(KeyCertUtility.getResourceSet().getString("CertInstallSetTrustPage", "pageTitle"));
        setLayout(new GridBagLayout());

	ResourceSet resource = KeyCertUtility.getResourceSet();

	JLabel purposeLabel = new JLabel(resource.getString("CertInstallSetTrustPage", "purposeLabel"));


	int y = 0;

	clientTrust = new JCheckBox(resource.getString("CertInstallSetTrustPage", "trustClientLabel"), 
				    true);
	serverTrust = new JCheckBox(resource.getString("CertInstallSetTrustPage", "trustServerLabel"), 
				    true); 

	GridBagUtil.constrain(this, purposeLabel,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

	GridBagUtil.constrain(this, clientTrust,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

	GridBagUtil.constrain(this, serverTrust,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

	GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        m_canMoveForward = true;
    }

    /*public static void main(String args[]) {
	JFrame f = new JFrame();
	f.getContentPane().add(new CertInstallSetTrustPage());
	f.setSize(400,400);
	f.show();
    }*/

}
