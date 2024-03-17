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

import com.netscape.management.client.components.*;
import java.awt.*;
import java.util.*;
import java.net.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.console.*;

class CertMigrateConfirmPage /*extends JPanel*/ extends WizardPage implements SuiConstants {

    ResourceSet resource;
    JTextField path;
    JTextField fromServer;

    ConsoleInfo _consoleInfo;
    Help help; 
    

    public String getStepName() {
        return i18n("title");
    }


    public void pageShown() {
	fromServer.setText(getDataModel().getValue("source").toString());
    }

    private String i18n(String id)
    {
        return resource.getString("CertMigrateConfirmPage", id);
    }

    public boolean nextInvoked() {
        boolean go = false;

	try {
            Hashtable args = new Hashtable();
            args.put("formop", "MIGRATE_DB");
            args.put("alias", getDataModel().getValue("alias"));
	    args.put("old_server_root", getDataModel().getValue("source"));
            args.put("sie", getDataModel().getValue("sie"));
            args.put("keypwd", getDataModel().getValue("keypwd"));

            AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                                  "admin-serv/tasks/configuration/SecurityOp"),
                                          _consoleInfo.getAuthenticationDN(),
                                          _consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            admTask.exec();
	    Debug.println(admTask.getResultString().toString());

	    if (!SecurityUtil.showError(admTask)) {
		JOptionPane.showMessageDialog(this, 
					      i18n("complete"),
					      i18n("completeTitle"), 
					      JOptionPane.INFORMATION_MESSAGE); 
		go = true;
	    }

	} catch (Exception e) {
	    SecurityUtil.printException("CertMigrateConfirmPage::nextInvoked()",e);
	}

	return go;

    }

    public CertMigrateConfirmPage(ConsoleInfo consoleInfo) {
	//super();
        super("");
        setLayout(new GridBagLayout());
	_consoleInfo = consoleInfo;

        resource = KeyCertUtility.getResourceSet();

	help = new Help(resource);

	//new ResourceSet("com.netscape.management.client.security.securityResource");

	JLabel from = new JLabel(i18n("copyFrom"));
	JLabel to = new JLabel(i18n("copyTo"));
	MultilineLabel warning = new MultilineLabel(i18n("warning"));
	fromServer = new JTextField();
	fromServer.setBackground(this.getBackground());
	fromServer.setEnabled(false);
    from.setLabelFor(fromServer);

	int y = 0;
        GridBagUtil.constrain(this, from,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, fromServer,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, to,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, warning,
                              0, ++y, 1, 1,
                              0.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, COMPONENT_SPACE, 0);

	m_canMoveForward = true;
	
    }

    /*public static void main(String arg[]) {
	JFrame f = new JFrame();
	f.getContentPane().add(new CertMigrateConfirmPage());
	f.setSize(400,300);
	f.show();
    }*/

    public void helpInvoked() {
	help.contextHelp(i18n("help"));
    }
}
