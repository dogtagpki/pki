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
import java.awt.event.*;
import java.util.*;
import java.net.*;
import javax.swing.*;
import javax.swing.event.*;

import com.netscape.management.client.components.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * Manage pkcs#11 device (or security device as we call it under our new UI)
 *
 * This will allow user to install or remove a PKCS#11 module
 *
 */
public class PKCSConfigDialog extends AbstractDialog implements SuiConstants {


    ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

    InstallPKCSDialog installPKCSDialog;

    //call cgi here to get data from the server.
    JList moduleList;
    String _sie;
    ConsoleInfo _consoleInfo;

    Help help; 


    /*public static void main(String args[]) {
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

	PKCSConfigDialog pkcsConfig = new PKCSConfigDialog(f, consoleInfo, "admin-serv-buddha");
	pkcsConfig.show();
	System.exit(0);
    }*/

    class ButtonPanel extends JPanel implements ActionListener, ListSelectionListener {
        JButton close/*ok, cancel*/, bHelp, install, remove;
        public ButtonPanel() {
            super();
            setLayout(new GridBagLayout());

            /*ok     = JButtonFactory.createOKButton(this);
            cancel = JButtonFactory.createCancelButton(this);*/
            close     = JButtonFactory.createCloseButton(this);
            bHelp   = JButtonFactory.createHelpButton(this);
            install    = JButtonFactory.create(resource.getString("PKCSConfigDialog", "installButtonLabel"), this, "INSTALL");
            install.setToolTipText(resource.getString("PKCSConfigDialog", "installButton_tt"));
            remove = JButtonFactory.create(resource.getString("PKCSConfigDialog", "removeButtonLabel"), this, "REMOVE");
            remove.setToolTipText(resource.getString("PKCSConfigDialog", "removeButton_tt"));
	    remove.setEnabled(false);

	    JButtonFactory.resizeGroup(close, bHelp, install, remove);

            int y = 0;

            GridBagUtil.constrain(this, close/*ok*/,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.NONE,
                                  0, 0, COMPONENT_SPACE, 0);

            /*GridBagUtil.constrain(this, cancel,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.NONE,
                                  0, 0, SEPARATED_COMPONENT_SPACE, 0);*/

            GridBagUtil.constrain(this, bHelp,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.NONE,
                                  0, 0, SEPARATED_COMPONENT_SPACE, 0);

            GridBagUtil.constrain(this, Box.createVerticalGlue(),
                                  0, ++y, 1, 1,
                                  0.0, 1.0,
                                  GridBagConstraints.WEST, GridBagConstraints.VERTICAL,
                                  0, 0, COMPONENT_SPACE, 0);

            GridBagUtil.constrain(this, install,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.NONE,
                                  0, 0, COMPONENT_SPACE, 0);

            GridBagUtil.constrain(this, remove,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.NONE,
                                  0, 0, 0, 0);

        }

	public void valueChanged(ListSelectionEvent e) {
            Object selection = moduleList.getSelectedValue();
            if (selection == null) {
		remove.setEnabled(false);
	    } else if (selection.toString().toLowerCase().startsWith("nss internal")){
		remove.setEnabled(false);
	    } else if (selection.toString().toLowerCase().startsWith("root certs")){
		remove.setEnabled(false);
	    } else {
		remove.setEnabled(true);
	    }
	}

	
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("INSTALL")) {
                installPKCSDialog.setVisible(true);
		if (installPKCSDialog.isModuleAdded()) {
		    PKCSConfigDialog.this.setVisible(true);
		    moduleAdded = installPKCSDialog.isModuleAdded();
		}
            } else if (e.getActionCommand().equals("REMOVE")) {
		try {
            
		    setBusyCursor(true);
            
		    Hashtable args = new Hashtable();
		    args.put("formop", "MODULE_OPERATION");
		    args.put("dllname", moduleList.getSelectedValue());
		    args.put("op_type", "remove");
		    args.put("sie", _sie);

		    AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
							  "admin-serv/tasks/configuration/SecurityOp"),
						  _consoleInfo.getAuthenticationDN(),
						  _consoleInfo.getAuthenticationPassword());

		    admTask.setArguments(args);

		    admTask.exec();
		    Debug.println(admTask.getResultString().toString());

		    ErrorDialog errorDialog = null;

		    if (admTask.getStatus() != 0) {
                   Dialog owner = (Dialog)SwingUtilities.getAncestorOfClass(Dialog.class, this);
			errorDialog = new ErrorDialog(owner,
						      (String)(admTask.getResult("NMC_ErrType")),
						      (String)(admTask.getResult("NMC_ErrInfo")));
			errorDialog.setIcon(ErrorDialog.ERROR_ICON);


			errorDialog.hideDetail();
			ModalDialogUtil.setDialogLocation(errorDialog,PKCSConfigDialog.this);
			errorDialog.show();
		    } else {
			PKCSConfigDialog.this.moduleRemoved = true;
		    }

		    PKCSConfigDialog.this.setVisible(true);
		} catch (Exception ex) {
		    Debug.println(ex.toString());
		}
		finally {
              setBusyCursor(false);
        }
            /*} else if (e.getActionCommand().equals("OK")) {
                System.out.println("not yet implemented");*/
            } else if (e.getActionCommand().equals("CLOSE"/*"CANCEL"*/)) {
                PKCSConfigDialog.this.cancelInvoked();
            } else if (e.getActionCommand().equals("HELP")) {
		help.contextHelp("PKCSConfigDialog", "help");
            }
        }
    }


    protected void cancelInvoked() {
        super.cancelInvoked();
    }

    public void setVisible(boolean visible) {
	//call cgi here to get data from the server.
	if (visible) {
	    try {

		setBusyCursor(true);

		Hashtable args = new Hashtable();
		args.put("formop", "LIST_MODULE");
		args.put("sie", _sie);
		Debug.println(9, args.toString());

		AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
						      "admin-serv/tasks/configuration/SecurityOp"),
					      _consoleInfo.getAuthenticationDN(),
					      _consoleInfo.getAuthenticationPassword());

		admTask.setArguments(args);

		admTask.exec();
		Debug.println(admTask.getResultString().toString());

		if (admTask.getStatus() == 0) {
		    Parser tokens = new Parser(admTask.getResultString().toString());
		    Hashtable mList = new Hashtable();

		    String typeKeyword;
		    while (tokens.hasMoreElement()) {
			typeKeyword = tokens.nextToken();

			if (typeKeyword.equals("<MODULES>")) {
			    mList = tokens.getTokenObject(typeKeyword);
			    break;
			}
		    }

		    Enumeration keys = mList.keys();
		    Vector tmpList = new Vector();
		    while (keys.hasMoreElements()) {
			tmpList.addElement(keys.nextElement());
		    }

		    moduleList.setListData(tmpList);
		} else {
		    //print error here
		}
	    } catch (Exception e) {
                if (Debug.isEnabled()) {
		    e.printStackTrace();
                }
	    }
		finally {
              setBusyCursor(false);
        }        
	}

	super.setVisible(visible);
	
    }

    boolean moduleAdded = false;
    boolean moduleRemoved = false;

    /**
     * Query to see if a device has been add.
     * this function will reset the status
     *
     * @return true if one or more security device has been successfully added
     */
    public boolean isModuleAdded() {
	boolean added = moduleAdded;
	moduleAdded = false;
	return added;
    }


    /**
     * Query to see if a device has been add.
     * this function will reset the status
     * 
     * @return true if one or more security device has been successfully removed
     */
    public boolean isModuleRemoved() {
	boolean removed = moduleRemoved;
	moduleRemoved = false;
	return removed;
    }

    /**
     * Construct a PKCS#11 management dialog
     *
     * @param parent the frame that lunches this dialog
     * @param consoleInfo contain admin server connection information
     * @param sie server instance name (ie. admin-serve-HOSTNAME) 
     */
    public PKCSConfigDialog(Component parent, ConsoleInfo consoleInfo, String sie) {
        super((parent instanceof Frame)?(Frame)parent:null, "", true, NO_BUTTONS , VERTICAL_BUTTONS);

	this._sie = sie;
	this._consoleInfo = consoleInfo;

	help = new Help(resource);

        getContentPane().setLayout(new GridBagLayout());

        setTitle(resource.getString("PKCSConfigDialog", "title"));

        JLabel availableToken = new JLabel(resource.getString("PKCSConfigDialog", "installedModuleLabel"));

        installPKCSDialog= new InstallPKCSDialog(this, consoleInfo, sie);

        moduleList = new JList();
        moduleList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        SuiScrollPane scrollpane = new SuiScrollPane(moduleList);

        int y = 0;

        GridBagUtil.constrain(getContentPane(), availableToken,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);


        GridBagUtil.constrain(getContentPane(), scrollpane,
                              0, ++y, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

	ButtonPanel buttonPanel = new ButtonPanel();
	moduleList.addListSelectionListener(buttonPanel);
        GridBagUtil.constrain(getContentPane(), buttonPanel,
                              1, 0, 1, y+1,
                              0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.VERTICAL,
                              0, SEPARATED_COMPONENT_SPACE, 0, 0);

        pack();
    }
}
