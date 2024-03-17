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
import com.netscape.management.client.components.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class InstallPKCSDialog extends AbstractDialog implements SuiConstants{


    JTextField moduleDriver = new JTextField();
    JTextField moduleName   = new JTextField();

    ConsoleInfo _consoleInfo;
    String _sie;
    Help help; 

    /**
     * Called when HELP button is pressed
     */
    protected void helpInvoked() {
        help.contextHelp("InstallPKCSDialog", "help");
    }

    public InstallPKCSDialog(Component parent, ConsoleInfo consoleInfo, String sie) {
        super((parent instanceof Frame)?(Frame)parent:null, "", true, OK | CANCEL | HELP, HORIZONTAL);

        this._consoleInfo = consoleInfo;
        this._sie = sie;

        getContentPane().setLayout(new GridBagLayout());

        ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");

        help = new Help(resource);

        setTitle(resource.getString("InstallPKCSDialog", "title"));

        JLabel moduleDriverLabel    = new JLabel(resource.getString("InstallPKCSDialog", "moduleDriverLabel"));
        moduleDriverLabel.setLabelFor(moduleDriverLabel);
        MultilineLabel moduleDriverExtLabel = new MultilineLabel(resource.getString("InstallPKCSDialog", "moduleDriverExtLabel"));
        JLabel moduleNameLabel      = new JLabel(resource.getString("InstallPKCSDialog", "moduleNameLabel"));
        moduleNameLabel.setLabelFor(moduleName);

        ActionListener listener = new ActionListener() {
                public void actionPerformed(ActionEvent event) {
                    if (event.getActionCommand().equals("BROWSE")) {
                        System.out.println("Not yet implemented");
                    }
                }
            };

        //JButton browse = JButtonFactory.create(resource.getString("InstallPKCSDialog", "browseButtonLabel"), listener, "BROWSE");


        int y = 0;

        GridBagUtil.constrain(getContentPane(), moduleDriverLabel,
                              0, y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), moduleDriver,
                              0, ++y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        /*GridBagUtil.constrain(getContentPane(), browse,
          1, y, 1, 1,
          0.0, 0.0,
          GridBagConstraints.EAST, GridBagConstraints.NONE,
          0, COMPONENT_SPACE, 0, 0);*/


        GridBagUtil.constrain(getContentPane(), moduleDriverExtLabel,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(getContentPane(), moduleNameLabel,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), moduleName,
                              0, ++y, 2, 1,
                              1.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        pack();
        if (getSize().width < 400) {
            setSize(400, getSize().height+20);
        }

    }

    boolean moduleAdded;
    public boolean isModuleAdded() {
        return moduleAdded;
    }

    protected void okInvoked() {
        String format = (moduleDriver.getText().endsWith(".dll") ||
                         moduleDriver.getText().endsWith(".so")  ||
                         moduleDriver.getText().endsWith(".sl"))? "dll":"jar";
        try {

            setBusyCursor(true);

            moduleAdded = false;
            Hashtable args = new Hashtable();
            args.put("formop", "MODULE_OPERATION");
            args.put("filename", moduleDriver.getText());
            args.put("format", format);
            args.put("dllname", moduleName.getText());
            args.put("op_type", "add");
            args.put("sie", _sie);

            AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                                  "admin-serv/tasks/configuration/SecurityOp"),
                                          _consoleInfo.getAuthenticationDN(),
                                          _consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            admTask.exec();
            Debug.println(admTask.getResultString().toString());


            ErrorDialog errorDialog = null;

            if (!SecurityUtil.showError(admTask)) {
                moduleAdded = true;
            } 

        } catch (Exception e) {
            SecurityUtil.printException("InstallPKCSDialog::okInvoked()",e);
        }
        finally {
            setBusyCursor(false);
        }

        if (moduleAdded) {
            super.okInvoked();
        }
    }
}
