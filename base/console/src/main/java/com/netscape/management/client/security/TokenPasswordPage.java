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
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;
import com.netscape.management.client.security.csr.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class TokenPasswordPage extends JPanel implements IUIPage, SuiConstants, DocumentListener {


    SingleBytePasswordField pwd = new SingleBytePasswordField();
    JTextField token = new JTextField();
    ResourceSet resource = KeyCertUtility.getResourceSet();
    IDataCollectionModel _sessionData;

    boolean canProceed = false;
    public void changedUpdate(DocumentEvent event) {
        Document document = event.getDocument();

        if (document == pwd.getDocument()) {
            _sessionData.setValue("keypwd", pwd.getText());

            if (pwd.getText().length() != 0) {
                canProceed = true;
            } else {
                canProceed = false;
            }
        }

        ((WizardDataCollectionModel)_sessionData).fireChangeEvent();
    }

    public void insertUpdate(DocumentEvent event) {
        changedUpdate(event);
    }

    public void removeUpdate(DocumentEvent event) {
        changedUpdate(event);
    }

    public Component getComponent() {
	return this;
    }

    public void addChangeListener(ChangeListener l) {}

    public void removeChangeListener(ChangeListener l) {}

    public boolean isPageValidated() {
	return canProceed;
    }

    public IUIPage getPreviousPage() {
	return null;
    }

    public IUIPage getNextPage() {
	return null;
    }

    public String getHelpURL() {
	return "TokenPasswordPage";
    }
    
    int remainingPageCount = 1;
    public void setRemainingPageCount(int pageCount) {
	remainingPageCount = pageCount;
    }
    public int getRemainingPageCount() {
	return remainingPageCount;
    }

    public String getPageName() {
	return KeyCertUtility.getResourceSet().getString("TokenPasswordPage", "pageTitle");
    }

    public TokenPasswordPage(IDataCollectionModel sessionData) {
	super();
	_sessionData = sessionData;
        setLayout(new GridBagLayout());

        pwd.getDocument().addDocumentListener(this);

        token.setEditable(false);
        token.setBackground(getBackground());
        if (sessionData != null) {
            token.setText((String)(sessionData.getValue("tokenname", "")));
        }

        int y = 0;

        MultilineLabel lblExplain = new MultilineLabel(resource.getString("TokenPasswordPage", "explain"));
        lblExplain.setLabelFor(token);

        GridBagUtil.constrain(this,
                              lblExplain,
                              0, y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, token,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);

        MultilineLabel lblPassword = new MultilineLabel(resource.getString("TokenPasswordPage", "passwordLabel"));
        lblPassword.setLabelFor(pwd);
        
        GridBagUtil.constrain(this,
                              lblPassword,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, pwd,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              1, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 2, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

    }

    static public void main(String[] args) {
        JFrame frame = new JFrame();
        frame.getContentPane().add(new TokenPasswordPage((IDataCollectionModel)null));
        frame.show();
    }

}
