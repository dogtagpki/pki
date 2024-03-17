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
package com.netscape.management.client.topology;

import java.util.*;
import java.awt.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.SuiLookAndFeel;
import com.netscape.management.nmclf.SuiOptionPane;
import com.netscape.management.client.util.AdmTask;
import com.netscape.management.client.console.ConsoleInfo;
import java.net.URL;

/**
 * Dialog which presents the keys available in the old server root
 * to migrate. User must select the specific key, and provide the new
 * alias and password for the key.
 *
 */
public class KeyCertMigrationDialog extends AbstractDialog {
    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    public static final int OLD_SERVER_VERSION_3 = 3;
    public static final int OLD_SERVER_VERSION_4 = 4;

    JLabel _aliasORsie = new JLabel("", JLabel.RIGHT);

    //JTextField     _oldServerRoot = new JTextField();
    JLabel _oldServerRoot = new JLabel();
    Component _alias;
    JLabel _oldServerVersion =
            new JLabel(Integer.toString(OLD_SERVER_VERSION_3) + ".x");

    SingleBytePasswordField _passwd = new SingleBytePasswordField();
    Help _helpSession; // support for help.

    ConsoleInfo _consoleInfo;
    Frame _parent;


    String _newServerRoot = "";
    String _sie = "";

    public KeyCertMigrationDialog(Frame parent,
            ConsoleInfo consoleInfo, String oldServerRoot,
            String aliasName, String newServerRoot, String sie) {
        this(parent, consoleInfo, oldServerRoot, (Object) aliasName,
                newServerRoot, sie, "");
    }

    public KeyCertMigrationDialog(Frame parent,
            ConsoleInfo consoleInfo, String oldServerRoot,
            String aliasName, String newServerRoot, String sie,
            String password) {
        this(parent, consoleInfo, oldServerRoot, (Object) aliasName,
                newServerRoot, sie, password);
    }

    public KeyCertMigrationDialog(Frame parent,
            ConsoleInfo consoleInfo, String oldServerRoot,
            Vector aliasList, String newServerRoot, String sie,
            String password) {
        this(parent, consoleInfo, oldServerRoot, (Object) aliasList,
                newServerRoot, sie, password);
    }

    private KeyCertMigrationDialog(Frame parent,
            ConsoleInfo consoleInfo, String oldServerRoot,
            Object alias, String newServerRoot, String sie,
            String password) {
        super(parent,
                _resource.getString("KeyCertMigrationDialog", "Title"),
                true, OK | CANCEL | HELP);

        _parent = parent;
        _oldServerRoot.setText(oldServerRoot);
        _newServerRoot = newServerRoot;
        _sie = sie;
        _passwd.setText(password);
        _helpSession = new Help(_resource);
        _consoleInfo = consoleInfo;
        JPanel infoPane = new JPanel();
        infoPane.setLayout(new GridBagLayout());

        int y = 0;
        JPanel fromPane = new JPanel();
        fromPane.setLayout(new GridBagLayout());
        GridBagUtil.constrain(fromPane,
                new JLabel(
                _resource.getString("KeyCertMigrationDialog", "from")),
                0, y, 2, 1, 0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.NONE, 0, 0, 0,
                SuiLookAndFeel.COMPONENT_SPACE);

        JLabel lblOldServerRoot = new JLabel( _resource.getString("KeyCertMigrationDialog",
                                                                  "oldServerRoot"), JLabel.RIGHT);
        lblOldServerRoot.setLabelFor(_oldServerRoot);
        GridBagUtil.constrain(fromPane,
                              lblOldServerRoot, 0, ++y, 1, 1, 0.0,
                              0.0, GridBagConstraints.EAST, GridBagConstraints.NONE,
                              SuiLookAndFeel.COMPONENT_SPACE, 0, 0,
                              SuiLookAndFeel.COMPONENT_SPACE);
        
        GridBagUtil.constrain(fromPane, _oldServerRoot, 1, y, 1, 1,
                              1.0, 0.0, GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              SuiLookAndFeel.COMPONENT_SPACE, 0, 0, 0);
        
        _aliasORsie.setText(
                _resource.getString("KeyCertMigrationDialog", "alias"));

        GridBagUtil.constrain(fromPane, _aliasORsie, 0, ++y, 1, 1, 0.0,
                              0.0, GridBagConstraints.EAST, GridBagConstraints.NONE,
                              SuiLookAndFeel.COMPONENT_SPACE, 0, 0,
                              SuiLookAndFeel.COMPONENT_SPACE);
        
        if ((alias != null) && (alias instanceof String)) {
            _alias = new JTextField((String) alias);
        } else if ((alias != null) && (alias instanceof Vector)) {
            _alias = new JComboBox((Vector) alias);
            ((JComboBox)_alias).setEditable(true);
            try {
                ((JComboBox)_alias).setSelectedIndex(0);
            } catch (Exception e) {
                Debug.println(e.toString());
            }
        } else {
            _alias = new JTextField();
        }

        _aliasORsie.setLabelFor(_alias);

        GridBagUtil.constrain(fromPane, _alias, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0, 0);

        JLabel lblPassword = new JLabel(_resource.getString("KeyCertMigrationDialog", "pwd"),
                                        JLabel.RIGHT);
        lblPassword.setLabelFor(_passwd);
        
        GridBagUtil.constrain(fromPane,
                              lblPassword , 0, ++y, 1, 1, 0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE,
                              SuiLookAndFeel.COMPONENT_SPACE, 0, 0,
                              SuiLookAndFeel.COMPONENT_SPACE);
        
        GridBagUtil.constrain(fromPane, _passwd, 1, y, 1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              SuiLookAndFeel.COMPONENT_SPACE, 0, 0, 0);
        
        JLabel lblOldServerVer = new JLabel( _resource.getString("KeyCertMigrationDialog",
                                                                 "oldServerVer"), JLabel.RIGHT);
        lblOldServerVer.setLabelFor(_oldServerVersion);
        GridBagUtil.constrain(fromPane,
                              lblOldServerVer, 0, ++y, 1, 1, 0.0,
                              0.0, GridBagConstraints.EAST, GridBagConstraints.NONE,
                              SuiLookAndFeel.COMPONENT_SPACE, 0, 0,
                              SuiLookAndFeel.COMPONENT_SPACE);
        
        GridBagUtil.constrain(fromPane, _oldServerVersion, 1, y, 1, 1,
                              1.0, 0.0, GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              SuiLookAndFeel.COMPONENT_SPACE, 0, 0, 0);
        
        GridBagUtil.constrain(fromPane, Box.createVerticalGlue(), 0,
                              ++y, 2, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                              GridBagConstraints.BOTH, 0, 0, 0, 0);
        
        GridBagUtil.constrain(infoPane, fromPane, 0, 0, 1, 1, 1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                              0, 0, SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE);

        getContentPane().add(infoPane);

        pack();
        setMinimumSize(300, getSize().height);
    }



    public void setMigrateFromVersion(int version) {
        if (version < OLD_SERVER_VERSION_4) {
            _aliasORsie.setText(
                    _resource.getString("KeyCertMigrationDialog", "alias"));
        } else {
            _aliasORsie.setText(
                    _resource.getString("KeyCertMigrationDialog", "sie"));
        }
    }

    public void setOldServerRoot(String oldServerRoot) {
        _oldServerRoot.setText(oldServerRoot);
    }

    public void setAlias(String alias) {
        if (_alias instanceof JTextField) {
            ((JTextField)_alias).setText(alias);
        } else if (_alias instanceof JComboBox) {
            ((JComboBox)_alias).setSelectedItem(alias);
            ((JComboBox)_alias).setSelectedItem(alias);
        }

    }

    public void setNewServerRoot(String newServerRoot) {
        _newServerRoot = newServerRoot;
    }

    public void setSIE(String sie) {
        _sie = sie;
    }

    public void setPassword(String password) {
        _passwd.setText(password);
    }


    public String getOldServerRoot() {
        return _oldServerRoot.getText();
    }

    public String getAlias() {
        String val = "";
        if (_alias instanceof JTextField) {
            val = ((JTextField)_alias).getText();
        } else if (_alias instanceof JComboBox) {
            val = ((JComboBox)_alias).getSelectedItem().toString();
        }
        return val;
    }

    public String getNewServerRoot() {
        return _newServerRoot;
    }

    public String getSIE() {
        return _sie;
    }

    public String getPassword() {
        return _passwd.getText();
    }


    /**
      * Implements the method to handle help event.
      */
    protected void helpInvoked() {
        _helpSession.contextHelp("topology", "kcmd");
    }

    /**
      * Called when OK button is pressed
      */
    protected void okInvoked() {
        try {
            AdmTask admTask = new AdmTask(
                    new URL(_consoleInfo.getAdminURL() + "admin-serv/tasks/configuration/KeyCertMigration"),
                    _consoleInfo.getAuthenticationDN(),
                    _consoleInfo.getAuthenticationPassword());

            Hashtable args = new Hashtable();
            //if (true) {
            args.put("newServerRoot", _newServerRoot);
            args.put("oldServerRoot", _oldServerRoot.getText());
            args.put("oldServVer",
                    _oldServerVersion.getText().substring(0, 1));
            args.put("alias", getAlias());
            args.put("sie", _sie);
            args.put("password", _passwd.getText());
            /*} else {
            args.put("conf_file", );
            args.put("newAlias", _sie);
            args.put("password", _passwd.getText());
        } */

            admTask.setArguments(args);
            admTask.exec();

            if (admTask.getStatus() != 0) {
                SuiOptionPane.showMessageDialog(_parent,
                        admTask.getResult("NMC_ErrDetail"));
            } else {
                SuiOptionPane.showMessageDialog(_parent,
                        admTask.getResult("NMC_Description"));
                this.dispose();
            }
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(_parent,
                    _resource.getString("KeyCertMigrationDialog", "fail"));
        }
    }

    public void show() {
        if (_parent == null) {
            _parent = UtilConsoleGlobals.getActivatedFrame();
            setParentFrame((JFrame)_parent);
        }
        super.show();
    }


    /*public static void main(String arg[]) {
     JFrame f = new JFrame();

     try {
      UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
      SwingUtilities.updateComponentTreeUI(f.getContentPane());
     } catch (Exception e) {}

         ConsoleInfo consoleInfo = null;
         try {
             consoleInfo = new ConsoleInfo("buddha.mcom.com", 8081, "admin", "admin", "o=mcom.com");
             consoleInfo.setAdminURL("https://buddha.mcom.com:8081/");
             consoleInfo.setBaseDN("cn=admin-serv-buddha, ou=Netscape SuiteSpot, o=mcom.com");
             consoleInfo.setCurrentDN("cn=admin-serv-buddha, ou=Netscape SuiteSpot, o=mcom.com");
         } catch (Exception e) {}

     KeyCertMigrationDialog d = new KeyCertMigrationDialog(f, consoleInfo, "C:\\kingpin", "admin-serv-buddha", "C:\\tmp", "admin-serv-buddha", "netscape@911");
     d.setMigrateFromVersion(OLD_SERVER_VERSION_4);
     d.show();
     }*/
}
