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
import java.util.*;
import java.net.*;
import javax.swing.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class EditTrustDialog extends AbstractDialog implements SuiConstants {

    JCheckBox clientTrust, serverTrust;

    //this number matches what is defined under NSS.
    //this might be a bad idea, but parsing string on both cgi
    //and console code might not be a good idea either
    public static int TRUSTED_CA       = 16;
    public static int TRUSTED_CLIENT_CA  = 128;

    int trust;
    String _sie, _certname, _certfingerprint;
    ConsoleInfo _consoleInfo;
    Component _parent;

    public EditTrustDialog(Component parent, 
			   ConsoleInfo consoleInfo,
			   String sie, 
			   String certName,
               String certFingerprint, 
			   String trustString) {
        super((parent instanceof Frame)?(Frame)parent:null, "", true, OK|CANCEL);

	this._sie = sie;
	this._certname = certName;
    this._certfingerprint = certFingerprint;
	this._consoleInfo = consoleInfo;
	this._parent = parent;

	ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

	setTitle(resource.getString("EditTrustDialog", "title")+" "+certName);

	JLabel purposeLabel = new JLabel(resource.getString("EditTrustDialog", "purposeLabel"));

	int y = 0;

	trust = 0;
	try {
	    //try to get the trust bit of the cert
	    //if the cert do not have a trust bit
	    //then we will assume not thing has been set
	    trust = Integer.parseInt(trustString);
	} catch (Exception e) {
	}

	clientTrust = new JCheckBox(resource.getString("EditTrustDialog", "trustClientLabel"),
				    ((trust & TRUSTED_CLIENT_CA) == TRUSTED_CLIENT_CA));
	serverTrust = new JCheckBox(resource.getString("EditTrustDialog", "trustServerLabel"),
				    ((trust & TRUSTED_CA) == TRUSTED_CA));

	Container p = getContentPane();
	p.setLayout(new GridBagLayout());
  
	GridBagUtil.constrain(p, purposeLabel,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

	GridBagUtil.constrain(p, clientTrust,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

	GridBagUtil.constrain(p, serverTrust,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

	GridBagUtil.constrain(p, Box.createVerticalGlue(),
                              0, ++y, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

	//setSize(400,175);
	pack();
    }

    public int getTrust() {
	return trust;
    }

    public void okInvoked() {
	int t = (clientTrust.isSelected()?TRUSTED_CLIENT_CA:0) |
	        (serverTrust.isSelected()?TRUSTED_CA:0);
	if (t != trust) {
	    try {
		Hashtable args = new Hashtable();
		args.put("formop", "CHANGE_TRUST");
		args.put("sie", _sie);
		args.put("certname", _certname);
		args.put("certfingerprint", _certfingerprint);
		args.put("trust_flag", Integer.toString(t));

		AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
						      "admin-serv/tasks/configuration/SecurityOp"),
					      _consoleInfo.getAuthenticationDN(),
					      _consoleInfo.getAuthenticationPassword());

		admTask.setArguments(args);
	    
		admTask.exec();
		Debug.println(admTask.getResultString().toString());


		if (!SecurityUtil.showError(admTask)) {
		    trust = t;
		} else {
		    return;
		}
	    } catch (Exception e) {
		SecurityUtil.printException("EditTrustDialog::okInvoked()",e);
	    }
	}
	super.okInvoked();
    }
}
