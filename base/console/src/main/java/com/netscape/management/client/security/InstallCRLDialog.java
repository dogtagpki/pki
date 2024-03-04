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

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.net.*;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class InstallCRLDialog extends AbstractDialog implements SuiConstants {

    ConsoleInfo _consoleInfo;
    String _sie;

    JTextField filename = new JTextField();
    JRadioButton crl, krl;

    Help help; 

    /**
      * Called when HELP button is pressed
      */
    protected void helpInvoked() {
	help.contextHelp("InstallCRLDialog", "help");
    }

    public void okInvoked() {
	try {
	    Hashtable args = new Hashtable();
	    args.put("formop", "INSTALL_CRL_CKL");
	    args.put("sie", _sie);
	    args.put("filename", filename.getText());
	    args.put("list_type", krl.isSelected()?"CKL":"CRL");
	    //just pass in anything for installmethod for install to occure
	    //if installmethod parameter is no pass in it is consider decode
	    args.put("installmethod", "1");

	    AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
						  "admin-serv/tasks/configuration/SecurityOp"),
					  _consoleInfo.getAuthenticationDN(),
					  _consoleInfo.getAuthenticationPassword());

	    admTask.setArguments(args);

	    admTask.exec();
	    
	    if (SecurityUtil.showError(admTask)) {
	    } else {
		setVisible(false);
	    }
	} catch (Exception e) {
	    Debug.println(e.toString());
	}
    }

    public InstallCRLDialog(Component parent, 
			    ConsoleInfo consoleInfo, 
			    String sie) {
        super((parent instanceof Frame)?(Frame)parent:null, "", true, OK|CANCEL|HELP);

        this._consoleInfo = consoleInfo;
        this._sie = sie;

	ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

	help = new Help(resource);
	
	setTitle(resource.getString("InstallCRLDialog", "title"));

        // Create a text area that looks like a multi-line label.
        JTextArea description = new JTextArea(resource.getString("InstallCRLDialog", "description"));
        description.setLineWrap(true);
        description.setWrapStyleWord(true);
        description.setMargin(UIManager.getInsets("Label.margin"));
        description.setBackground(UIManager.getColor("Label.background"));
        description.setForeground(UIManager.getColor("Label.foreground"));
        description.setFont(UIManager.getFont("Label.font"));

	JLabel enterFile = new JLabel(resource.getString("InstallCRLDialog", "enterFilename"));
        enterFile.setLabelFor(filename);
	crl = new JRadioButton(resource.getString("InstallCRLDialog", "crl"), true);
	krl = new JRadioButton(resource.getString("InstallCRLDialog", "krl"), false);
	ButtonGroup g = new ButtonGroup();
	g.add(crl);
	g.add(krl);

	getContentPane().setLayout(new GridBagLayout());
	
        int y = 0;

        GridBagUtil.constrain(getContentPane(), description,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(getContentPane(), enterFile,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(getContentPane(), filename,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(getContentPane(), crl,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), krl,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        // We need to pack twice to prevent our text area from being truncated.
	pack();
        pack();
	setResizable(false);
    }

    public static void main(String arg[]) {
	JFrame f = new JFrame();
	InstallCRLDialog d = new InstallCRLDialog(f, new ConsoleInfo(), "admin-buddha");
	d.show();
    }
}

