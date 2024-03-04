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
import com.netscape.management.client.components.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;



public class SetTokenPwdDialog extends AbstractDialog implements SuiConstants {

    SingleBytePasswordField oldPwd, pwd, confirmPwd;

    Help help; 

    ConsoleInfo _consoleInfo;
    String _sie;
    boolean _isNew;
    String _tokenName;

    public static void main(String args[]) {
      try {
          UIManager.setLookAndFeel(new SuiLookAndFeel());
      } catch (Exception e) {}
      Debug.setTrace(true);
      
      JFrame f = new JFrame();
      ConsoleInfo consoleInfo = new ConsoleInfo();
      consoleInfo.setAuthenticationDN("admin");
      consoleInfo.setAuthenticationPassword("admin");
      consoleInfo.setAdminURL("http://god:8081/");
      consoleInfo.setPort(8081);
      consoleInfo.setHost("god");
      
      SetTokenPwdDialog tokenPwd = new SetTokenPwdDialog(f, consoleInfo, "admin-serv-god", true, "test");
      tokenPwd.show();
      System.exit(0);
      }
    
    /**
     * Called when HELP button is pressed
     */
    protected void helpInvoked() {
        help.contextHelp("SetTokenPwdDialog", "help");
    }
    
    public SetTokenPwdDialog(Component parent, ConsoleInfo consoleInfo, String sie, boolean isNew, String tokenName) {
        super((parent instanceof Frame)?(Frame)parent:null, "", true, OK | CANCEL | HELP, VERTICAL_BUTTONS);


        _consoleInfo = consoleInfo;
        _sie = sie;
        _isNew = isNew;
        _tokenName = tokenName;

        getContentPane().setLayout(new GridBagLayout());

        ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

        help = new Help(resource);

        if (isNew) {
            setTitle(resource.getString("SetTokenPwdDialog", "titleSetPwd"));
        } else {
            setTitle(resource.getString("SetTokenPwdDialog", "titleChangePwd"));
        }

        MultilineLabel definationLabel = new MultilineLabel(resource.getString("SetTokenPwdDialog", "defination"));

        JLabel oldPwdLabel = new JLabel(resource.getString("SetTokenPwdDialog", "oldPwd"));
        JLabel newPwdLabel = new JLabel(resource.getString("SetTokenPwdDialog", "newPwd"));
        JLabel confirmPwdLabel = new JLabel(resource.getString("SetTokenPwdDialog", "confirmPwd"));
        MultilineLabel recommandPwd = new MultilineLabel(resource.getString("SetTokenPwdDialog", "pwdRule"));        
		recommandPwd.setPreferredSize(new Dimension(250, 50));
        MultilineLabel pwdNotSet = new MultilineLabel(resource.getString("SetTokenPwdDialog", "pwdNotSet"));
        pwdNotSet.setPreferredSize(new Dimension(250, 50));

        oldPwd     = new SingleBytePasswordField();
        oldPwdLabel.setLabelFor(oldPwd);
        
        pwd        = new SingleBytePasswordField();
        newPwdLabel.setLabelFor(pwd);
        
        confirmPwd = new SingleBytePasswordField();
        confirmPwdLabel.setLabelFor(confirmPwd);

        setFocusComponent(pwd);

        int y = 0;

        GridBagUtil.constrain(getContentPane(), definationLabel, 0, y, 2, 1, 1.0,
                              0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);


        if (isNew) {
            GridBagUtil.constrain(getContentPane(), pwdNotSet, 0, ++y, 2, 1, 1.0,
                                  0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                  0, 0, DIFFERENT_COMPONENT_SPACE, 0);
        } else {
            GridBagUtil.constrain(getContentPane(), oldPwdLabel, 0, ++y, 2, 1, 1.0,
                                  0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                                  0, 0, 0, 0);

            GridBagUtil.constrain(getContentPane(), oldPwd, 0, ++y, 2, 1, 0.0,
                                  0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                                  0, 0, DIFFERENT_COMPONENT_SPACE, 0);
            
            setFocusComponent(oldPwd);            
        }

        GridBagUtil.constrain(getContentPane(), newPwdLabel, 0, ++y, 2, 1, 1.0,
                              0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), pwd, 0, ++y, 2, 1, 0.0,
                              0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(getContentPane(), confirmPwdLabel, 0, ++y, 2, 1, 1.0,
                              0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), confirmPwd, 0, ++y, 2, 1, 1.0,
                              0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(getContentPane(), new JLabel(UIManager.getIcon("OptionPane.warningIcon")), 
                              0, ++y, 1, 1, 
                              1.0, 0.0, 
                              GridBagConstraints.NORTH, GridBagConstraints.NONE,
                              0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), recommandPwd, 1, y, 1, 1, 1.0,
                              0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(getContentPane(), Box.createVerticalGlue(),
                              0, ++y, 2, 1,
                              0.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);


        //setResizable(false);
        //setSize(400,275);
        pack();
    }


    public void needInit() {
        try {
            Hashtable args = new Hashtable();

            args.put("sie", _sie);
            args.put("tokenname", _tokenName);
            args.put("formop", "NEED_INIT");

            AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                                  "admin-serv/tasks/configuration/SecurityOp"),
                                          _consoleInfo.getAuthenticationDN(),
                                          _consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            admTask.exec();
            Debug.println(admTask.getResultString().toString());


            if (admTask.getStatus() == 0) {
                Hashtable result = admTask.getResult();

                try {
                    if (((String)result.get("NMC_Description")).equals("TRUE")) {
                        setVisible(true);
                    }
                } catch (Exception no_description) {
                    //assume no init is needed
                    Debug.println("SetTokenPwdDialog no init.");
                }
            }
        } catch (Exception e) {
            Debug.println(e.toString());
        }
    }


    public void setVisible(boolean visible) {

        if (visible) {
            oldPwd.setText("");
            pwd.setText("");
            confirmPwd.setText("");
            setSize(getPreferredSize());
        }

        super.setVisible(visible);        
    }
    
    protected void okInvoked() {
        try {

            setBusyCursor(true);

            Hashtable args = new Hashtable();

            args.put("sie", _sie);

            if (_isNew) {
                args.put("formop", "INIT_PIN");
            } else {
                args.put("formop", "CHANGE_PASSWORD");
                args.put("oldpwd", oldPwd.getText());
            }

            args.put("newpwd", pwd.getText());
            args.put("confirmpwd", confirmPwd.getText());
            args.put("tokenname", _tokenName);
	    

            AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                                  "admin-serv/tasks/configuration/SecurityOp"),
                                          _consoleInfo.getAuthenticationDN(),
                                          _consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            admTask.exec();
            Debug.println(admTask.getResultString().toString());

            if (admTask.getStatus() != 0) {
                Hashtable result = admTask.getResult();
                //display error
                ErrorDialog errorDialog = new ErrorDialog(this,
                                                          (String)result.get("NMC_ErrType"),
                                                          (String)(result.get("NMC_ErrDetail")));

                errorDialog.hideDetail();
                ModalDialogUtil.setDialogLocation(errorDialog,this);
                errorDialog.show();
                //Display error here
                Debug.println(admTask.getResultString().toString());
            } else {
                setVisible(false);
            }

        } catch (Exception e) {
            Debug.println(e.toString());
        }
        finally {
            setBusyCursor(false);
        }
    }
}
