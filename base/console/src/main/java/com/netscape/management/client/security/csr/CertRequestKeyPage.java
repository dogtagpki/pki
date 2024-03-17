/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2013 Red Hat, Inc.
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
package com.netscape.management.client.security.csr;

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


public class CertRequestKeyPage extends JPanel implements SuiConstants, IUIPage {

    JComboBox keySize;
    JComboBox signingAlgo;

    ResourceSet resource = new ResourceSet("com.netscape.management.client.security.KeyCertWizardResource");

    JLabel _keySizeLabel, _signingAlgoLabel;

    Hashtable _sessionData;

    public Component getComponent() {
	return this;
    }

    public String getPageName() {
	return resource.getString("CertRequestKeyPage", "pageTitle");
    }
    public int getRemainingPageCount() {
	return 1;
    }

    public IUIPage getNextPage() {
	return (validated()?null:this);
    }

    public IUIPage getPreviousPage() {
	return null;
    }

    public void addChangeListener(ChangeListener l) {
    }

    public void removeChangeListener(ChangeListener l) {
    }

    public String getHelpURL() {
	return "CertRequestKeyPage";
    }

    private JLabel rightAlignLabel(String label) {
        return new JLabel(label, JLabel.RIGHT);
    }

    public boolean isPageValidated() {
	return true;
    }

    public boolean validated() {
        // Fill in our keysize and signingalgo session data.
	String keySize_str = (String)keySize.getSelectedItem();
	if (keySize_str == null) {
	    keySize_str = "";
	}
	_sessionData.put("keysize" , keySize_str);

	String signingAlgo_str = (String)signingAlgo.getSelectedItem();
	if (signingAlgo_str == null) {
	    signingAlgo_str = "";
	}
	_sessionData.put("signingalgo" , signingAlgo_str);
	
        // There is really nothing to validate, so just return true.
        return true;
    }

    public CertRequestKeyPage(Hashtable sessionData) {
	super();

	_sessionData = sessionData;

        setLayout(new GridBagLayout());

        // Get the list of supported key sizes and signing algorithms.
        String keysizeList = resource.getString("CertRequestKeyPage", "keysizes");
        String signingalgoList = resource.getString("CertRequestKeyPage", "signingalgos");

        // Populate the key sizes combo box.
        StringTokenizer keysizeTokens =
	    new StringTokenizer(keysizeList, ",", false);
        Vector keysizes = new Vector();

        while (keysizeTokens.hasMoreTokens()) {
            keysizes.addElement(keysizeTokens.nextToken());
        }
	
        keySize = new JComboBox(keysizes);

        // Populate the signing algorithms combo box.
        StringTokenizer signingalgoTokens =
            new StringTokenizer(signingalgoList, ",", false);
        Vector signingalgos = new Vector();

        while (signingalgoTokens.hasMoreTokens()) {
            signingalgos.addElement(signingalgoTokens.nextToken());
        }

        signingAlgo = new JComboBox(signingalgos);
	
        // Add our labels.
        _keySizeLabel = rightAlignLabel(resource.getString("CertRequestKeyPage", "keySizeLabel"));
	_keySizeLabel.setLabelFor(keySize);

        _signingAlgoLabel = rightAlignLabel(resource.getString("CertRequestKeyPage", "signingAlgoLabel"));
	_signingAlgoLabel.setLabelFor(signingAlgo);

        // Set our default selections.
        try {
            keySize.setSelectedItem(resource.getString("CertRequestKeyPage", "defaultKeySize"));
            signingAlgo.setSelectedItem(resource.getString("CertRequestKeyPage", "defaultSigningAlgo"));
        } catch (Exception e) {
            Debug.println(e.toString());
        }

        setupBasicPanel();
    }

    private void setupBasicPanel() {
        removeAll();

        int y = 0;

        // Add our UI elements.
        GridBagUtil.constrain(this, _keySizeLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, keySize, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, _signingAlgoLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, signingAlgo, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 2, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);
    }
}
