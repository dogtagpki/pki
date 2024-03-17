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

class CertInstallTypePage extends WizardPage implements SuiConstants {

    JTextField forServer, certName;
    ResourceSet resource = KeyCertUtility.getResourceSet();
    ResourceSet resource_theme = KeyCertUtility.getResourceSetTheme();

    public void pageShown() {
        IDataCollectionModel dataModel = getDataModel();
        forServer.setText((String)(dataModel.getValue("serverType", resource_theme.getString("CertInstallTypePage", "defaultServerName"))) +
                          " (" +
                          (String)(dataModel.getValue("sie", resource_theme.getString("CertInstallTypePage", "defaultSIE"))) +
                          ")");

	if (dataModel.getValue("certtype").equals(Integer.toString(CertInstallWizard.CA))) {
	    CertificateList certList = (CertificateList)(dataModel.getValue("certlist"));
	    Vector cert = (Vector)(certList.getCACerts());
	    certName.setText(KeyCertUtility.getCertName((Hashtable)(cert.elementAt(0))));

	    certName.setEnabled(false);	    
	} else {
	    certName.setText((String)(dataModel.getValue("certname", "server-cert")));
	}
    }


    public CertInstallTypePage() {
        super(KeyCertUtility.getResourceSet().getString("CertInstallTypePage", "pageTitle"));
        setLayout(new GridBagLayout());

        MultilineLabel forServerLabel = new MultilineLabel(resource.getString("CertInstallTypePage", "forServerLabel"));
        forServer = new JTextField();
        forServerLabel.setLabelFor(forServer);
        forServer.setEditable(false);
        forServer.setBackground(this.getBackground());

        MultilineLabel certNameLabel = new MultilineLabel(resource.getString("CertInstallTypePage", "certNameLabel"));
        certName = new JTextField();
        certNameLabel.setLabelFor(certName);
        //certName.setBackground(this.getBackground());
        
        
        MultilineLabel certTypeLabel = new MultilineLabel(resource.getString("CertInstallTypePage", "certTypeLabel"));
        
        JRadioButton serverCert = new JRadioButton(resource.getString("CertInstallTypePage", "thisServerLabel"),true);
        JRadioButton certChain  = new JRadioButton(resource.getString("CertInstallTypePage", "certChainLabel"),false);
        JRadioButton trustedCA  = new JRadioButton(resource.getString("CertInstallTypePage", "caLabel"),false);
        
        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(serverCert);
        buttonGroup.add(certChain);
        buttonGroup.add(trustedCA);

        m_canMoveForward = true;

        int y = 0;

        GridBagUtil.constrain(this, forServerLabel,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, forServer,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);

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

        GridBagUtil.constrain(this, serverCert,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, DIFFERENT_COMPONENT_SPACE, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, certChain,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, DIFFERENT_COMPONENT_SPACE, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, trustedCA,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, DIFFERENT_COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);
    }

    /*public static void main(String arg[]) {
        JFrame f = new JFrame();
        f.getContentPane().add("North", new CertInstallCertInfoPage());
        f.setSize(400,400);
        f.show();
    }*/

}
