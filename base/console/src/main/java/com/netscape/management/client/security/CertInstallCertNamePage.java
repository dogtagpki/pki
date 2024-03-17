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
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.console.ConsoleInfo;

class CertInstallCertNamePage extends WizardPage implements SuiConstants {

    JTextField certName, certType;
    ResourceSet resource = KeyCertUtility.getResourceSet();
    String _sie, _tokenName;
    ConsoleInfo _consoleInfo;

    public void pageShown() {
        IDataCollectionModel dataModel = getDataModel();

	if (dataModel.getValue("certtype").equals(Integer.toString(CertInstallWizard.CA))) {
	    CertificateList certList = (CertificateList)(dataModel.getValue("certlist"));
	    Vector cert = (Vector)(certList.getCACerts());
	    if ((cert == null) || cert.isEmpty()) {
	        cert = (Vector)(certList.getServerCerts());
	    }
	    if ((cert == null) || cert.isEmpty()) {
	        cert = (Vector)(certList.getCerts());	        
	    }
	    if ((cert != null) && !cert.isEmpty()) {
	        certName.setText(KeyCertUtility.getCertName((Hashtable)(cert.elementAt(0)), _tokenName, _consoleInfo, _sie));
	    }
	    certName.setEnabled(false);	    
	    certType.setText(resource.getString("CertInstallCertNamePage", "caCert"));
	} else {
        String certname = (String)dataModel.getValue("certname");
        if (certname != null) {
            certName.setText(certname);
            certName.setEditable(false);
        }
        else {
	        certName.setText("server-cert");
        }
	    certType.setText(resource.getString("CertInstallCertNamePage", "serverCert"));
	}

    }

    public boolean nextInvoked() {
        IDataCollectionModel model = getDataModel();

	model.setValue("certname" , certName.getText());

        return true;
    }

    public void helpInvoked() {
	KeyCertUtility.getHelp().contextHelp("CertInstallCertNamePage", "help");
    }
    

    public CertInstallCertNamePage(String tokenName, String sie, ConsoleInfo consoleInfo) {
        super(KeyCertUtility.getResourceSet().getString("CertInstallCertNamePage", "pageTitle"));

        this._sie = sie;
        this._tokenName = tokenName;
        this._consoleInfo = consoleInfo;

        setLayout(new GridBagLayout());

        MultilineLabel certNameLabel = new MultilineLabel(resource.getString("CertInstallCertNamePage", "certNameLabel"));
        certName = new JTextField();
        //certName.setBackground(this.getBackground());
        certNameLabel.setLabelFor(certName);

        MultilineLabel certTypeLabel = new MultilineLabel(resource.getString("CertInstallCertNamePage", "certTypeLabel"));

        m_canMoveForward = true;

        int y = 0;

        GridBagUtil.constrain(this, certNameLabel,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, certName,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, certTypeLabel,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

	certType = new JTextField("");
    certTypeLabel.setLabelFor(certType);
	certType.setEnabled(false);
	certType.setBackground(getBackground());
	
        GridBagUtil.constrain(this, certType,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.VERTICAL,
                              0, 0, 0, 0);

     }

}
