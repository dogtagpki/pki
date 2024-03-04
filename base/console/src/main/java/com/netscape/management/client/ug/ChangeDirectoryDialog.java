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

package com.netscape.management.client.ug;

import java.awt.*;
import javax.swing.*;
import com.netscape.management.client.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.topology.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.preferences.*;
import netscape.ldap.*;


/**
 * ChangeDirectoryDialog allows end users to change the users and groups
 * directory server that is used for searching and creating new user/group/ou
 * objects. It remembers the directory server that the end user has chosen
 * as the user's preferences.
 *
 * Change History:
 * 31 Aug 1998  Disabled preferences loading/saving to fix security hole.
 *              Any changes made to the user/group directory server is per
 *              session only. To make permanent changes, users can modify
 *              the User DS configuration in the Admin Server Console.
 */
public class ChangeDirectoryDialog extends AbstractDialog {

    private static final String PREFERENCES_SEARCH_DIRECTORY = "SearchBaseDN";
    private static final String PREFERENCE_HOST = "Host";
    private static final String PREFERENCE_PORT = "Port";
    private static final String PREFERENCE_BASE_DN = "BaseDN";
    private static final String PREFERENCE_AUTH_DN = "AuthDN";
    private static final String PREFERENCE_AUTH_PASSWORD = "AuthPassword";
    private static final String PREFERENCE_SSL = "SSL";

    ConsoleInfo _info;
    boolean _fChanged;

    JCheckBox _ssl;
    JTextField _host;
    JTextField _port;
    JTextField _baseDN;
    JTextField _username;
    SuiPasswordField _password;

    ResourceSet _resource = TopologyInitializer._resource;
    static final String _sChangeDirectory = "ChangeDirectory";
    private Help _helpSession; // support for help.


    /**
     * Constructor creates the dialog
     *
     * @param frame  the parent JFrame
     * @param info   session info
     */
    public ChangeDirectoryDialog(JFrame frame, ConsoleInfo info) {
        super(frame,
              TopologyInitializer._resource.getString("General",
                                                      _sChangeDirectory), true, OK | CANCEL | HELP);
        _helpSession = new Help(_resource);
        _info = info;
        _fChanged = false;

        //loadPreferences();
        initializeUI();
    }


    /**
     * Creates and lays out the visual components for the dialog
     */
    private void initializeUI() {
        GridBagLayout layout = new GridBagLayout();

        JPanel p = new JPanel();
        p.setLayout(layout);

        JLabel lblHost = new JLabel( _resource.getString(_sChangeDirectory, "Host"),
                                     JLabel.RIGHT);
        GridBagUtil.constrain(p,
                              lblHost, 0, 0, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST,
                              GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        
        JLabel lblPort = new JLabel( _resource.getString(_sChangeDirectory, "Port"),
                                     JLabel.RIGHT);
        GridBagUtil.constrain(p,
                              lblPort, 0, 1, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        JLabel lblBaseDN = new JLabel( _resource.getString(_sChangeDirectory, "BaseDN"),
                                       JLabel.RIGHT);
        GridBagUtil.constrain(p,
                              lblBaseDN, 0, 2, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        JLabel lblUserName = new JLabel( _resource.getString(_sChangeDirectory, "Username"),
                                         JLabel.RIGHT);
        GridBagUtil.constrain(p,
                              lblUserName, 0, 3, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        JLabel lblPassword = new JLabel( _resource.getString(_sChangeDirectory, "Password"),
                                         JLabel.RIGHT);
        GridBagUtil.constrain(p,
                              lblPassword, 0, 4, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        JLabel blankLabel = new JLabel("");
        GridBagUtil.constrain(p, blankLabel, 0, 5,
                              GridBagConstraints.REMAINDER,
                              GridBagConstraints.REMAINDER, 1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        _host = new JTextField();
        lblHost.setLabelFor(_host);
        _host.setText(_info.getUserHost());
        GridBagUtil.constrain(p, _host, 1, 0,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _port = new JTextField();
        lblPort.setLabelFor(_port);
        _port.setText(Integer.toString(_info.getUserPort()));
        GridBagUtil.constrain(p, _port, 1, 1,
                              GridBagConstraints.RELATIVE, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _ssl = new JCheckBox(_resource.getString(_sChangeDirectory, "ssl"));
        GridBagUtil.constrain(p, _ssl, 2, 1, 1, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        LDAPConnection ldc = _info.getUserLDAPConnection();
        if (ldc != null && ldc.isConnected()) {
            _ssl.setSelected(
                             _info.getUserLDAPConnection().getSocketFactory() !=
                             null);
        }

        _baseDN = new JTextField();
        lblBaseDN.setLabelFor(_baseDN);
        _baseDN.setText(_info.getUserBaseDN());
        GridBagUtil.constrain(p, _baseDN, 1, 2,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _username = new JTextField();
        lblUserName.setLabelFor(_username);
        _username.setText(_info.getAuthenticationDN());
        GridBagUtil.constrain(p, _username, 1, 3,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _password = new SuiPasswordField();
        lblPassword.setLabelFor(_password);
        _password.setText(_info.getAuthenticationPassword());
        GridBagUtil.constrain(p, _password, 1, 4,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        setPanel(p);
        setMinimumSize(getPreferredSize());
    }


    /**
     * Checks to see whether any value has been changed.
     *
     * @return true if any value has been changed; false otherwise
     */
    public boolean isDirectoryChange() {
        return _fChanged;
    }


    /**
     * Displays the dialog, reinitializing all of the values as necessary.
     * This allows the dialog to be reused, since any canceled changes will
     * not remain from a previous usage.
     */
    public void show() {
        reinitializeFields();
        super.show();
    }


    /**
     * Convenience routine to reset all field values.
     */
    private void reinitializeFields() {
        _host.setText(_info.getUserHost());
        _port.setText(Integer.toString(_info.getUserPort()));

        LDAPConnection ldc = _info.getUserLDAPConnection();
        if (ldc != null && ldc.isConnected()) {
            _ssl.setSelected(
                             _info.getUserLDAPConnection().getSocketFactory() !=
                             null);
        }

        _baseDN.setText(_info.getUserBaseDN());
        _username.setText(LDAPUtil.getUIDFromDN(ldc, _info.getAuthenticationDN()));
        _password.setText(_info.getAuthenticationPassword());
    }


    /**
     * Handles action to set the new values for the directory server.
     */
    protected void okInvoked() {
        String userDN = LDAPUtil.getDNFromUID(_host.getText(), 
                                              Integer.parseInt(_port.getText()),
                                              _ssl.isSelected(),
                                              LDAPUtil.getConfigurationRoot(),
                                              _username.getText());

        if (userDN == null) {
            userDN = _username.getText();
        }

        try {
            KingpinLDAPConnection ldc;
            if (_ssl.isSelected()) {
                ldc = new KingpinLDAPConnection(
                                                UtilConsoleGlobals.getLDAPSSLSocketFactory(),
                                                userDN, 
                                                _password.getText());
            } else {
                ldc = new KingpinLDAPConnection(userDN,
                                                _password.getText());
            }
            ldc.connect(LDAPUtil.LDAP_VERSION, _host.getText(),
                        Integer.parseInt(_port.getText()),
                        userDN, _password.getText());
            if (isValidBaseDN(ldc, _baseDN.getText())) {
                LDAPConnection oldConnection =
                    _info.getUserLDAPConnection();
                _info.setUserHost(_host.getText());
                _info.setUserPort(Integer.parseInt(_port.getText()));
                _info.setAuthenticationDN(userDN);
                _info.setAuthenticationPassword(_password.getText());
                _info.setUserBaseDN(_baseDN.getText());
                _info.setUserLDAPConnection(ldc);
                if ((oldConnection != null) &&
                    (oldConnection.isConnected())) {
                    oldConnection.disconnect();
                }
                //savePreferences();
                _fChanged = true;
                super.okInvoked();
            }
        }
        catch (Exception e) {
            // cannot connect
            SuiOptionPane.showMessageDialog(null, /*_info.getFrame(),*/
                                            _resource.getString("error","cannotconnect") + e,
                                            _resource.getString("error","title"),
                                            SuiOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();
        }
    }


    /**
     * Determines whether the specified base DN is valid. Simply, it does a check
     * to see if there are any object classes available at the base DN. If the
     * base DN is valid, the search will succeed. If the base DN does not exist,
     * the search will fail.
     *
     * @param ldc           the connection to the directory server
     * @param searchBaseDN  the base DN to test
     * @return              true if the searchBaseDN is valid; false otherwise
     */
    private boolean isValidBaseDN(LDAPConnection ldc, String searchBaseDN) {
        try {
            LDAPSearchResults tmp = ldc.search(searchBaseDN,
                                               LDAPConnection.SCOPE_BASE, "(objectclass=*)",
                                               null, false);
            return true;
        } catch (LDAPException e) {
            SuiOptionPane.showMessageDialog(null,
                                            _resource.getString("error","invalidbasedn") + e,
                                            _resource.getString("error","title"),
                                            SuiOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();
            return false;
        }
    }


    /**
     * Displays help specific to this dialog.
     */
    protected void helpInvoked() {
        _helpSession.contextHelp("ug","ChangeDirectory");
    }


    /**
     * Loads values from the last saved preferences. If there are no saved
     * preferences, then the values are loaded from the ConsoleInfo object.
     */
    private void loadPreferences() {
        PreferenceManager pm = PreferenceManager.getPreferenceManager(
                                                                      Framework.IDENTIFIER, Framework.MAJOR_VERSION);
        Preferences p = pm.getPreferences(PREFERENCES_SEARCH_DIRECTORY);

        String host = p.getString(PREFERENCE_HOST, _info.getUserHost());
        int port = p.getInt(PREFERENCE_PORT, _info.getUserPort());
        String baseDN =
            p.getString(PREFERENCE_BASE_DN, _info.getUserBaseDN());
        String authDN = p.getString(PREFERENCE_AUTH_DN,
                                    _info.getAuthenticationDN());
        String authPassword = p.getString(PREFERENCE_AUTH_PASSWORD,
                                          _info.getAuthenticationPassword());

        LDAPConnection oldConnection = _info.getUserLDAPConnection();
        boolean useSSL = p.getBoolean(PREFERENCE_SSL,
                                      ((oldConnection != null) &&
                                       (oldConnection.getSocketFactory() != null)));

        LDAPConnection ldc = null;
        if (useSSL) {
            ldc = new KingpinLDAPConnection(
                                            UtilConsoleGlobals.getLDAPSSLSocketFactory(), 
                                            authDN, 
                                            authPassword);
        } else {
            ldc = new KingpinLDAPConnection(authDN, authPassword);
        }

        try {
            ldc.connect(LDAPUtil.LDAP_VERSION, host, port, authDN,
                        authPassword);
            _info.setUserLDAPConnection(ldc);
            if ((oldConnection != null) && (oldConnection.isConnected())) {
                oldConnection.disconnect();
            }
            _info.setUserHost(host);
            _info.setUserPort(port);
            _info.setUserBaseDN(baseDN);
            _info.setAuthenticationDN(authDN);
            _info.setAuthenticationPassword(authPassword);
        } catch (LDAPException e) {
            Debug.println(
                          "ChangeDirectoryDialog:loadPreferences:cannot connect to the directory server at " +
                          host + ":" + port);
        }
    }


    /**
     * Saves values as user preferences.
     */
    private void savePreferences() {
        PreferenceManager pm = PreferenceManager.getPreferenceManager(
                                                                      Framework.IDENTIFIER, Framework.MAJOR_VERSION);
        Preferences p = pm.getPreferences(PREFERENCES_SEARCH_DIRECTORY);

        p.set(PREFERENCE_HOST, _info.getUserHost());
        p.set(PREFERENCE_PORT, _info.getUserPort());
        p.set(PREFERENCE_BASE_DN, _info.getUserBaseDN());
        p.set(PREFERENCE_AUTH_DN, _info.getAuthenticationDN());
        p.set(PREFERENCE_AUTH_PASSWORD, _info.getAuthenticationPassword());
        p.set(PREFERENCE_SSL,
              ((_info.getUserLDAPConnection() != null) &&
               (_info.getUserLDAPConnection().getSocketFactory() !=
                null)));

        PreferenceManager.saveAllPreferences();
    }
}
