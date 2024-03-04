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
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class PromptTokenPasswordDialog extends AbstractDialog implements SuiConstants {


    SingleBytePasswordField pwd = new SingleBytePasswordField();
    JTextField token = new JTextField() {
        public boolean isFocusTraversable() {
            return false;
        }
    };

    public String getPassword() {
        return pwd.getText();
    }

    public void setPassword(String password) {
	pwd.setText(password);
    }

    public void setToken(String tokenName) {
	token.setText(tokenName);
    }

    public PromptTokenPasswordDialog(Component parent, String tokenName) {
        super((parent instanceof Frame)?(Frame)parent:null, "", true, OK | CANCEL/* | HELP*/, VERTICAL);
        getContentPane().setLayout(new GridBagLayout());

        ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

        setTitle(resource.getString("PromptTokenPasswordDialog", "title"));

        JLabel selectedToken = new JLabel(resource.getString("PromptTokenPasswordDialog", "selectedToken"));
        selectedToken.setLabelFor(token);

        JLabel enterPwd      = new JLabel(resource.getString("PromptTokenPasswordDialog", "enterPwd"));
        enterPwd.setLabelFor(pwd);

        token.setText(tokenName);
        token.setEditable(false);
        token.setBackground(getContentPane().getBackground());

        int y = 0;

        GridBagUtil.constrain(getContentPane(), selectedToken,
                              0, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0,
                              0,
                              DIFFERENT_COMPONENT_SPACE/2,
                              0);

        GridBagUtil.constrain(getContentPane(), token,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0,
                              0,
                              SEPARATED_COMPONENT_SPACE/2,
                              0);

        GridBagUtil.constrain(getContentPane(), enterPwd,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              SEPARATED_COMPONENT_SPACE/2,
                              0,
                              DIFFERENT_COMPONENT_SPACE/2,
                              0);
        
        GridBagUtil.constrain(getContentPane(), pwd,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);
                              
        this.setFocusComponent(pwd);
        
        pack();
        if (getSize().width < 400) {
            setSize(400, getSize().height);
        }
    }

    public void okInvoked() {
        if (pwd.getText().length() > 0) {
            super.okInvoked();
        }
    }

    public static void main(String arg[]) {
        try {
            UIManager.setLookAndFeel(new SuiLookAndFeel());
        } catch (Exception e) {}
        Debug.setTrace(true);
        
        JFrame f = new JFrame();
        PromptTokenPasswordDialog pwd= new PromptTokenPasswordDialog(f, "Internal (Software)");
        pwd.setVisible(true);
        System.out.println(pwd.getPassword());
    }
}
