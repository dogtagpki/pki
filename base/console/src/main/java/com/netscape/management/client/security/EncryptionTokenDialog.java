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

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.console.*;


class EncryptionTokenDialog extends AbstractDialog implements SuiConstants {


    PKCSConfigDialog pkcsConfigDialog;
    SetTokenPwdDialog setTokenPwdDialog;
    Help help; 

    ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

    ConsoleInfo _consoleInfo;
    String _sie, _selectedToken;

    ListTableModel tokenListTableModel;
    SuiTable tokenTable;
    String defaultToken;

    class ButtonPanel extends JPanel implements ActionListener, ListSelectionListener {
        JButton ok, cancel, bHelp, pwd/*, module*/;
        public ButtonPanel() {
            super();
            setLayout(new GridBagLayout());

            ok     = JButtonFactory.createOKButton(this);
            cancel = JButtonFactory.createCancelButton(this);
            bHelp   = JButtonFactory.createHelpButton(this);
            pwd    = JButtonFactory.create(resource.getString("EncryptionTokenDialog", "pwdButtonLabel"), this, "PASSWORD");
            /*module = JButtonFactory.create(resource.getString("EncryptionTokenDialog", "moduleButtonLabel"), this, "MODULE");
	    JButton buttons[] = new JButton[5];
	    buttons[0] = ok;
	    buttons[1] = cancel;
	    buttons[2] = help;
	    buttons[3] = pwd;
	    buttons[4] = module;
	    JButtonFactory.resize(ok);*/

	    JButtonFactory.resizeGroup(ok, cancel, bHelp, pwd);

            int y = 0;

            GridBagUtil.constrain(this, ok,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, COMPONENT_SPACE, 0);

            GridBagUtil.constrain(this, cancel,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, SEPARATED_COMPONENT_SPACE, 0);

            GridBagUtil.constrain(this, bHelp,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, SEPARATED_COMPONENT_SPACE, 0);

            GridBagUtil.constrain(this, Box.createVerticalGlue(),
                                  0, ++y, 1, 1,
                                  0.0, 1.0,
                                  GridBagConstraints.WEST, GridBagConstraints.VERTICAL,
                                  0, 0, COMPONENT_SPACE, 0);

            GridBagUtil.constrain(this, pwd,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, COMPONENT_SPACE, 0);

            /*GridBagUtil.constrain(this, module,
                                  0, ++y, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, 0, 0);*/

        }

        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("PASSWORD")) {
                EncryptionTokenDialog.this.setTokenPwdDialog.setVisible(true);
            /*} else if (e.getActionCommand().equals("MODULE")) {
                EncryptionTokenDialog.this.pkcsConfigDialog.setVisible(true);

                if (EncryptionTokenDialog.this.pkcsConfigDialog.isModuleAdded() ||
		    EncryptionTokenDialog.this.pkcsConfigDialog.isModuleRemoved()) {
		    EncryptionTokenDialog.this.setVisible(true);
		}*/
            } else if (e.getActionCommand().equals("OK")) {
		_selectedToken = (String)(tokenListTableModel.getValueAt(tokenTable.getSelectedRow(), 0));
                EncryptionTokenDialog.this.setVisible(false);
            } else if (e.getActionCommand().equals("CANCEL")) {
                EncryptionTokenDialog.this.cancelInvoked();
            } else if (e.getActionCommand().equals("HELP")) {
		help.contextHelp("EncryptionTokenDialog", "help");
            }
        }

	public void valueChanged(ListSelectionEvent e) {
	    if (((String)(tokenListTableModel.getValueAt(tokenTable.getSelectedRow(), 0))).toString().equals(defaultToken)){

		pwd.setEnabled(true);
	    } else {
		pwd.setEnabled(false);
	    }
	}
    }

    public String getSelectedToken() {
	return _selectedToken;
    }

    protected void cancelInvoked() {
        super.cancelInvoked();
    }

    public void setVisible(boolean visible) {
	//call cgi here to get data from the server.
	if (visible) {
	    try {
		Hashtable args = new Hashtable();
		args.put("formop", "LIST_TOKEN");
		args.put("sie", _sie);

		AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
						      "admin-serv/tasks/configuration/SecurityOp"),
					      _consoleInfo.getAuthenticationDN(),
					      _consoleInfo.getAuthenticationPassword());

		admTask.setArguments(args);

		admTask.exec();
		//System.out.println(admTask.getResultString().toString());

		if (admTask.getStatus() == 0) {
		    Parser tokens = new Parser(admTask.getResultString().toString());
		    Hashtable pkcs11TokenInfo = new Hashtable();

		    String typeKeyword;
		    while (tokens.hasMoreElement()) {
			typeKeyword = tokens.nextToken();

			if (typeKeyword.equals("<TOKENLIST>")) {
			    pkcs11TokenInfo = tokens.getTokenObject(typeKeyword);
			    break;
			}
		    }


		    Enumeration keys = pkcs11TokenInfo.keys();
		    Vector rowData = new Vector();
		    while (keys.hasMoreElements()) {
			String moduleName = (String)(keys.nextElement());
			if (moduleName.endsWith("_TOKEN")) {
			    Hashtable tokenName = (Hashtable)(pkcs11TokenInfo.get(moduleName));
			    Enumeration keys2 = tokenName.keys();
			    while (keys2.hasMoreElements()) {
				Vector row = new Vector();
				String temp = (String)(keys2.nextElement());
				row.addElement(temp);
				//row.addElement(moduleName.substring(0,moduleName.indexOf("_TOKEN")));
				row.addElement(((Hashtable)(tokenName.get(temp))).get("MODULE"));
				rowData.addElement(row);
			    }
			}
		    }
		    tokenListTableModel.setRowData(rowData);
		    int selectedIndex =tokenListTableModel.getSelectedRow(0, _selectedToken);
		    tokenTable.getSelectionModel().setSelectionInterval(selectedIndex, selectedIndex);
		} else {
		    //display error here
		}
	    } catch (Exception e) {
		Debug.println(e.toString());
	    }
	}

	super.setVisible(visible);
    }



    public EncryptionTokenDialog(Component parent, ConsoleInfo consoleInfo, String sie, String selectedToken) {
        super((parent instanceof Frame)?(Frame)parent:null, "", true, NO_BUTTONS , VERTICAL_BUTTONS);

	this._consoleInfo = consoleInfo;
	this._sie = sie;
	this._selectedToken = selectedToken;


	help = new Help(resource);


        getContentPane().setLayout(new GridBagLayout());

        setTitle(resource.getString("EncryptionTokenDialog", "title"));

	defaultToken = resource.getString("CertificateDialog", "defaultToken");	

        JLabel availableToken = new JLabel(resource.getString("EncryptionTokenDialog", "availableTokenLabel"));

        Vector columnNames = new Vector();
        columnNames.addElement(resource.getString("EncryptionTokenDialog", "nameLabel"));
        //columnNames.addElement(resource.getString("EncryptionTokenDialog", "moduleLabel"));


        pkcsConfigDialog = new PKCSConfigDialog(this, consoleInfo, sie);
        setTokenPwdDialog = new SetTokenPwdDialog(this, consoleInfo, sie, false, selectedToken);

        Vector rowData = new Vector();
        //call cgi here to get data from the server.

	tokenListTableModel = new ListTableModel(columnNames, rowData);
	tokenTable = new SuiTable(tokenListTableModel);
        SuiScrollPane scrollpane = new SuiScrollPane(tokenTable);

        int y = 0;

        GridBagUtil.constrain(getContentPane(), availableToken,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(getContentPane(), scrollpane,
                              0, ++y, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

	ButtonPanel buttonPanel = new ButtonPanel();
	tokenTable.getSelectionModel().addListSelectionListener(buttonPanel);
        GridBagUtil.constrain(getContentPane(), buttonPanel,
                              1, 0, 1, y+1,
                              0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, SEPARATED_COMPONENT_SPACE, 0, 0);

        setSize(400,300);
    }
}
