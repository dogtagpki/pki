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
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.console.*;

class CertMigrateAliasSelectionPage extends WizardPage implements SuiConstants {

    ResourceSet resource;
    ConsoleInfo _consoleInfo;

    MultilineLabel explain;
    JLabel selectAlias, enterPwd;
    SingleBytePasswordField pwd;
    Table aliasTable;
    Help help; 

    boolean pwdFieldVisible;


    public String getStepName() {
        return resource.getString("CertMigrateAliasSelectionPage", "title");
    }

    private void verifyCanGoForward() {
	getDataModel().setValue("keypwd", pwd.getText());

	int row = aliasTable.getSelectedRow();
	if (row != -1) {
	    getDataModel().setValue("alias", aliasTable.getValueAt(row, 0));
	}

	//can go forward only if at least one alias is selected
	//and if pwd field is visible pwd must be entered.
	m_canMoveForward = (row != -1) && (!pwdFieldVisible || (pwd.getText().length()!=0));

	((WizardDataCollectionModel)getDataModel()).fireChangeEvent();
    }

    /**
     * Call by wizard before it attempt to bring up the page for display
     *
     */
    public void pageShown() {
	removeAll();

	KeyListener keyListener = new KeyListener() {
	    public void keyTyped(KeyEvent e) {}
	    public void keyPressed(KeyEvent e) {}
	    public void keyReleased(KeyEvent e) {
		CertMigrateAliasSelectionPage.this.verifyCanGoForward();
	    }
	    };

	pwd.addKeyListener(keyListener);
	pwd.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		CertMigrateAliasSelectionPage.this.verifyCanGoForward();
	    }
	});

	int y = 0;
        GridBagUtil.constrain(this, explain,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, selectAlias,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

	Vector columnNames = new Vector();
	columnNames.addElement(resource.getString("CertMigrateAliasSelectionPage", "nameLabel"));

	aliasTable = new Table((Vector)(getDataModel().getValue("aliasList")), columnNames);
    selectAlias.setLabelFor(aliasTable);
	try {
	    aliasTable.getSelectionModel().setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);
	} catch (Exception e) {
	    Debug.println("CertMigrateAliasSelectionPage: EMPTY ALIAS LIST");
	}



	aliasTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
	    Hashtable versionList = (Hashtable)(getDataModel().getValue("aliasVersionList"));
	    public void valueChanged(ListSelectionEvent e) {
		int selected = aliasTable.getSelectedRow();
		if (selected != -1) {
		    if (versionList.get(aliasTable.getValueAt(selected, 0).toString()).equals("3")) {
			enterPwd.setVisible(true);
			pwd.setVisible(true);
			pwdFieldVisible = true;
		    } else {
			enterPwd.setVisible(false);
			pwd.setVisible(false);
			pwdFieldVisible = false;
		    }
		} 
	    }
	});

	aliasTable.addKeyListener(keyListener);

        aliasTable.addMouseListener(
		    new MouseListener() {
			    public void mouseClicked(MouseEvent e) {
				CertMigrateAliasSelectionPage.this.verifyCanGoForward();
			    }
			    public void mouseEntered(MouseEvent e) { }
			    public void mouseExited(MouseEvent e)  { }
			    public void mousePressed(MouseEvent e) { }
			    public void mouseReleased(MouseEvent e){ }
			});


	GridBagUtil.constrain(this, aliasTable,
			      0, ++y, 1, 1,
			      1.0, 1.0,
			      GridBagConstraints.NORTH, GridBagConstraints.BOTH,
			      0, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(this, enterPwd,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, pwd,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);
    }

    public CertMigrateAliasSelectionPage(ConsoleInfo consoleInfo) {
        super("");

	_consoleInfo = consoleInfo;
        setLayout(new GridBagLayout());
        resource = KeyCertUtility.getResourceSet();

	help = new Help(resource);

	    //new ResourceSet("com.netscape.management.client.security.securityResource");

	explain = new MultilineLabel(resource.getString("CertMigrateAliasSelectionPage", "explain"));
	selectAlias =  new JLabel(resource.getString("CertMigrateAliasSelectionPage", "selectLabel"));
	enterPwd = new JLabel(resource.getString("CertMigrateAliasSelectionPage", "enterPwd"));
	pwd = new SingleBytePasswordField(40);
    enterPwd.setLabelFor(pwd);

    }

    public void helpInvoked() {
	help.contextHelp("CertMigrateAliasSelectionPage", "help");
    }
}

