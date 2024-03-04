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
import java.awt.event.*;
import java.net.*;
import java.util.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.nmclf.*;

class CertMigrateSourcePage extends WizardPage implements SuiConstants {

    ResourceSet resource;
    JTextField path;

    ConsoleInfo _consoleInfo;
    Help help; 

    public String getStepName() {
        return resource.getString("CertMigrateSourcePage", "title");
    }

   private void verifyCanGoForward() {
	getDataModel().setValue("source", path.getText());
	m_canMoveForward = (path.getText().length()!=0);
	((WizardDataCollectionModel)getDataModel()).fireChangeEvent();
    }


    public boolean nextInvoked() {
        boolean go = false;
	/*create Table here*/
	try {
            Hashtable args = new Hashtable();
            args.put("formop", "LIST_ALIAS");
	    args.put("old_server_root", getDataModel().getValue("source"));
            args.put("sie", getDataModel().getValue("sie"));

            AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                                  "admin-serv/tasks/configuration/SecurityOp"),
                                          _consoleInfo.getAuthenticationDN(),
                                          _consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            admTask.exec();
	    Debug.println(admTask.getResultString().toString());

	    if (!SecurityUtil.showError(admTask)) {
		Parser parser = new Parser(admTask.getResultString().toString());
		Hashtable aliases = parser.getTokenObject("ALIAS");
		Vector aliasList = new Vector();
		Enumeration keys = ((Hashtable)(aliases.elements().nextElement())).keys();
		Hashtable aliasVersionList = new Hashtable();
		while (keys.hasMoreElements()) {
		    Vector item = new Vector();
		    String key = keys.nextElement().toString();
		    if (key.endsWith("-key.db")) {
			key = key.substring(0, key.indexOf("-key.db"));
			aliasVersionList.put(key, "3");
		    } else {
			key = key.substring(0, key.indexOf("-key3.db"));
			aliasVersionList.put(key, "4");
		    }
		    item.addElement(key);
		    aliasList.addElement(item);
		}

		getDataModel().setValue("aliasList", aliasList);
		getDataModel().setValue("aliasVersionList", aliasVersionList);

		go = true;
	    }

	} catch (Exception e) {
	    SecurityUtil.printException("CertMigrateSourcePage::nextInvoked()",e);
	}

	return go;
    }



    public CertMigrateSourcePage(ConsoleInfo consoleInfo) {
        super("");
        setLayout(new GridBagLayout());
	_consoleInfo = consoleInfo;

        resource = KeyCertUtility.getResourceSet();

	help = new Help(resource);

	    //new ResourceSet("com.netscape.management.client.security.securityResource");

	MultilineLabel explain = new MultilineLabel(resource.getString("CertMigrateSourcePage", "explain"));
	JLabel enterPath = new JLabel(resource.getString("CertMigrateSourcePage", "enterFileLabel"));
	path = new JTextField();
    enterPath.setLabelFor(path);

	path.addKeyListener(new KeyListener() {
	    public void keyTyped(KeyEvent e) {}
	    public void keyPressed(KeyEvent e) {}
	    public void keyReleased(KeyEvent e) {
		CertMigrateSourcePage.this.verifyCanGoForward();
	    }
	});
	path.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		CertMigrateSourcePage.this.verifyCanGoForward();
	    }
	});


	/*JButton browse = JButtonFactory.create(resource.getString("", "browseButtonLabel"));*/

	int y = 0;
        GridBagUtil.constrain(this, explain,
                              0, y, 2, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, enterPath,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, path,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        /*GridBagUtil.constrain(this, browse,
                              1, y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.NONE,
                              0, 0, COMPONENT_SPACE, 0);*/

	
	GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 1, 1,

                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.VERTICAL,
                              0, 0, COMPONENT_SPACE, 0);
    }

    public void helpInvoked() {
	help.contextHelp("CertMigrateSourcePage", "help");
    }
}
