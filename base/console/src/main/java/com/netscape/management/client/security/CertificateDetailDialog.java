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


import java.util.*;
import java.net.*;
import java.awt.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.nmclf.*;


class CertificateDetailDialog extends AbstractDialog implements SuiConstants {

    ResourceSet resource;
    Help help; 

    JTabbedPane tabbedPane;
    CertificateInfoPanels certInfo;
    Component general, detail, path;

    private void init(Hashtable cert) {
        resource = new ResourceSet("com.netscape.management.client.security.securityResource");

	setTitle(resource.getString("CertificateDetailDialog", "title"));

	certInfo = new CertificateInfoPanels(cert);

	/*certInfo.setDefaultBorder(new CompoundBorder(
                new MatteBorder(DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, getContentPane().getBackground()),
                new BevelBorder(BevelBorder.LOWERED, Color.white,
                getContentPane().getBackground(), Color.black, Color.black)));*/

	tabbedPane = new JTabbedPane(JTabbedPane.TOP);
	general = certInfo.getGeneralInfo();
	detail = certInfo.getDetailInfo();
	path = certInfo.getCertChainInfo();
	tabbedPane.addTab(resource.getString("CertificateDetailDialog", "generalTitle") , general);
	tabbedPane.addTab(resource.getString("CertificateDetailDialog", "detailTitle"),  detail);
	tabbedPane.addTab(resource.getString("CertificateDetailDialog", "pathTitle"),  path);

	getContentPane().setLayout(new GridBagLayout());
	GridBagUtil.constrain(getContentPane(), tabbedPane,
			      0, 0, 1, 1,
			      1.0, 1.0,
			      GridBagConstraints.NORTH, GridBagConstraints.BOTH,
			      0, 0, 0, 0);

	pack();
	setVisible(true);
    }


    /*
     * Called when HELP button is pressed
     */
    protected void helpInvoked() {
        Component c = tabbedPane.getSelectedComponent();

	if (c == general) {
	    help.contextHelp("CertificateDetailDialogGeneral", "help");
	} else if (c == detail) {
	    help.contextHelp("CertificateDetailDialogDetail", "help");
	} else if (c == path) {
	    help.contextHelp("CertificateDetailDialogPath", "help");
	}
    }

    public CertificateDetailDialog(JFrame parent, Hashtable cert) {
	super(parent, "", true, OK | HELP);
	resource = new ResourceSet("com.netscape.management.client.security.securityResource");
	help = new Help(resource);
	init(cert);
    }

    

    public CertificateDetailDialog(JFrame parent,
				 ConsoleInfo consoleInfo, 
				 String sie, 
				 String certname,
				 String fingerprint) {

	super(parent, "", true, OK | HELP);

        resource = new ResourceSet("com.netscape.management.client.security.securityResource");
	help = new Help(resource);

	setTitle(resource.getString("CertificateDetailDialog", "title"));

	try {
	    Hashtable args = new Hashtable();
	    args.put("formop", "FIND_CERTIFICATE");
	    args.put("sie", sie);
	    args.put("certname", certname);
	    args.put("certfingerprint", fingerprint);

	    AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
						  "admin-serv/tasks/configuration/SecurityOp"),
					  consoleInfo.getAuthenticationDN(),
					  consoleInfo.getAuthenticationPassword());

	    admTask.setArguments(args);
	    //admTask.exec();
	    //Debug.println(admTask.getResultString().toString());

        if (SecurityUtil.execWithPwdInput(admTask, args, null) &&
	        !SecurityUtil.showError(parent, admTask)) {
		CertificateList certList = new CertificateList(admTask.getResultString().toString());
		Hashtable cert = null;
		if (certList.getCACerts().size()!=0) {
		    cert = (Hashtable)(certList.getCACerts().elementAt(0));
		} else if (certList.getServerCerts().size() != 0) {
		    cert = (Hashtable)(certList.getServerCerts().elementAt(0));
		} else {
		    //no cert;
		    return;
		}

		init(cert);
	    }
	} catch (Exception e) {
	    SecurityUtil.printException("CertificateDetailDialog::CertificateDetailDialog(...)",e);
	}    
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
        CertificateDetailDialog d = new CertificateDetailDialog(f,
							    consoleInfo, 
							    "admin-serv-buddha", 
							    "Thawte Personal Premium CA");
							    //"server-cert2");

        d.setSize(640,480);

        d.show();
        System.exit(0);
    }*/
}


