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

import java.awt.*;
import javax.swing.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import netscape.ldap.*;


/**
 * Dialog for create new domain
 *
 * @author   terencek
 * @version  %I%, %G%
 */

public class NewDomainDialog extends AbstractDialog {
    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");
    private static String sNewDomain = "NewDomain";
    private static String sChangeDirectory = "ChangeDirectory";
    private Help _helpSession; // support for help.
    JTextField _tfDomainName;
    JCheckBox _ssl;
    SingleByteTextField _host;
    JTextField _port;
    JTextField _baseDN;
    JTextField _username;
    JTextField _ownerDN;
    SuiPasswordField _password;
    ConsoleInfo _info;

    /**
     * constructor
     *
     * @param parent parent frame
     * @param info global info
     */
    public NewDomainDialog(Frame parent, ConsoleInfo info) {
        super(parent, _resource.getString(sNewDomain, "title"), true,
                OK | CANCEL | HELP);

        _helpSession = new Help(_resource);
        _info = info;

        JLabel label =
            new JLabel(_resource.getString(sNewDomain, "DomainName"),
                       JLabel.RIGHT);
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(panel, label, 0, 0, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST,
                              GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        
        _tfDomainName = new JTextField();
        label.setLabelFor(_tfDomainName);
        GridBagUtil.constrain(panel, _tfDomainName, 1, 0,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);
        
        label = new JLabel(_resource.getString(sNewDomain, "UGHost"),
                           JLabel.RIGHT);
        GridBagUtil.constrain(panel,
                              label, 0, 1, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        _host = new SingleByteTextField();
        label.setLabelFor(_host);
        GridBagUtil.constrain(panel, _host, 1, 1,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);
        
        label = new JLabel(_resource.getString(sNewDomain, "UGPort"),
                           JLabel.RIGHT);
        GridBagUtil.constrain(panel,
                              label, 0, 2, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        _port = new JTextField(5);
        label.setLabelFor(_port);
        GridBagUtil.constrain(panel, _port, 1, 2,
                              GridBagConstraints.RELATIVE, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);


        
        _ssl = new JCheckBox(_resource.getString(sChangeDirectory, "ssl"));
        _ssl.setHorizontalAlignment(SwingConstants.RIGHT);
        GridBagUtil.constrain(panel, _ssl, 2, 2, 1, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHEAST, GridBagConstraints.NONE,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        label = new JLabel( _resource.getString(sNewDomain, "UGSubtree"),
                            JLabel.RIGHT);
        GridBagUtil.constrain(panel,
                              label, 0, 3, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        _baseDN = new JTextField();
        label.setLabelFor(_baseDN);
        GridBagUtil.constrain(panel, _baseDN, 1, 3,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);
        
        label = new JLabel(_resource.getString(sNewDomain, "BindDN"),
                           JLabel.RIGHT);
        GridBagUtil.constrain(panel,
                              label, 0, 4, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        _username = new JTextField();
        label.setLabelFor(_username);
        GridBagUtil.constrain(panel, _username, 1, 4,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);        
        
        label = new JLabel( _resource.getString(sNewDomain, "BindPassword"),
                            JLabel.RIGHT);
        GridBagUtil.constrain(panel,
                              label, 0, 5, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        _password = new SuiPasswordField();
        label.setLabelFor(_password);
        GridBagUtil.constrain(panel, _password, 1, 5,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        label = new JLabel(_resource.getString(sNewDomain, "ownerDN"),
                           JLabel.RIGHT);

        GridBagUtil.constrain(panel,
                              label, 0, 6, 1, 1, 0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
        
        _ownerDN = new JTextField();
        _ownerDN.setText(_info.getAuthenticationDN());
        label.setLabelFor(_ownerDN);
        GridBagUtil.constrain(panel, _ownerDN, 1, 6,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                              SuiConstants.SEPARATED_COMPONENT_SPACE,
                              SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);
        
        JLabel blankLabel = new JLabel("");
        GridBagUtil.constrain(panel, blankLabel, 0, 7,
                              GridBagConstraints.REMAINDER,
                              GridBagConstraints.REMAINDER, 1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);      
        
        setPanel(panel);
        setMinimumSize(350, 300);
    }

    /**
      * display help
      */
    public void helpInvoked() {
        _helpSession.contextHelp("topology", sNewDomain);
    }

    /**
      * ok button is hit
      */
    protected void okInvoked() {
        if (_tfDomainName.getText().length() == 0) {
            return;
        }

        for (;;) {
            LDAPEntry entry;
            LDAPAttributeSet attrs;
            LDAPConnection ldc = _info.getLDAPConnection();
            if (ldc == null) {
                SuiOptionPane.showMessageDialog(null,
                        _resource.getString(sNewDomain, "NullConnection"),
                        _resource.getString("error","title"),
                        SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return;
            }

            try {
                // create domain
                attrs = new LDAPAttributeSet();
                String sArray[] = {"top","organizationalunit","nsAdminDomain"};
                attrs.add(new LDAPAttribute("objectclass",sArray));
                attrs.add(new LDAPAttribute("ou",_tfDomainName.getText()));
                attrs.add( new LDAPAttribute("nsAdminDomainName",
                        _tfDomainName.getText()));

                String sDN = _ownerDN.getText();
                if ((sDN != null) && (!sDN.equals(""))) {
                    attrs.add( new LDAPAttribute("aci",
                            "(targetattr=*)(targetfilter=(ou="+
                            _tfDomainName.getText() + "))(version 3.0; acl \"Default anonymous access\"; allow(read,search) userdn=\"ldap:///anyone\";)"));
                    attrs.add( new LDAPAttribute("aci",
                            "(targetattr=*)(version 3.0; acl \"Domain owner access rights\";allow(all) userdn=\"ldap:///"+
                            sDN + "\";)"));
                }

                entry = new LDAPEntry("ou="+_tfDomainName.getText() + ", o=netscaperoot",
                        attrs);
                ldc.add(entry);

            } catch (LDAPException e) {
                Debug.println("NewDomainDialog: cannot create domain");
                break;
            }

            try {
                // create global preference
                attrs = new LDAPAttributeSet();
                String sArray[] = {"top","organizationalunit"};
                attrs.add(new LDAPAttribute("objectclass",sArray));
                attrs.add(new LDAPAttribute("ou","Global Preferences"));
                attrs.add(new LDAPAttribute("aci", "(targetattr=*)(version 3.0; acl \"Default anonymous access\"; allow(read,search) userdn=\"ldap:///anyone\";)"));

                entry = new LDAPEntry("ou=Global Preferences, ou="+
                        _tfDomainName.getText() + ", o=netscaperoot",
                        attrs);
                ldc.add(entry);

            } catch (LDAPException e) {
                Debug.println("NewDomainDialog: cannot create domain: ou=Global Preferences, ou="+
                        _tfDomainName.getText() + ", o=netscaperoot");
                try {
                    ldc.delete("ou="+_tfDomainName.getText() + ", o=netscaperoot");
                } catch (LDAPException e1) {
                }
                break;
            }

            // create the domain
            try {
                // create User directory
                attrs = new LDAPAttributeSet();
                String sArray[] = {"top","nsDirectoryInfo"};
                attrs.add(new LDAPAttribute("objectclass",sArray));
                attrs.add(new LDAPAttribute("cn","UserDirectory"));

                String sUG;
                String sFailoverList;
                int temp;

                if ((temp = (_host.getText()).indexOf(" ")) != -1) {
                    // failover list - first host & port is for nsDirectoryURL...
                    sUG = "ldap"+(_ssl.isSelected() ? "s":"") + "://"+
                            (_host.getText()).substring(0, temp) + "/"+
                            _baseDN.getText();
                    // ... and the rest is for nsDirectoryFailoverList
                    sFailoverList = _host.getText().substring(temp + 1);
                } else {
                    sUG = "ldap"+(_ssl.isSelected() ? "s":"") + "://"+
                            _host.getText() + ":"+_port.getText() + "/"+
                            _baseDN.getText();
                    sFailoverList = "";
                }


                Debug.println(sUG);
                Debug.println(sFailoverList);

                if ((sUG != null) && (!sUG.equals("")) &&
                        (sFailoverList != null)) {
                    attrs.add(new LDAPAttribute("nsdirectoryurl",sUG));
                    attrs.add( new LDAPAttribute("nsdirectoryfailoverlist",
                            sFailoverList));
                }
                String sDN = _username.getText();
                if ((sDN != null) && (!sDN.equals(""))) {
                    attrs.add(new LDAPAttribute("nsBindDN",sDN));
                }
                String sPassword = _password.getText();
                if ((sPassword != null) && (!sPassword.equals(""))) {
                    attrs.add(
                            new LDAPAttribute("nsBindPassword",sPassword));
                }

                entry = new LDAPEntry("cn=UserDirectory, ou=Global Preferences, ou="+
                        _tfDomainName.getText() + ", o=netscaperoot",
                        attrs);
                ldc.add(entry);

            } catch (LDAPException e) {
                Debug.println("NewDomainDialog: cannot create domain: cn=UserDirectory, ou=Global Preferences, ou="+
                        _tfDomainName.getText() + ", o=netscaperoot");
                try {
                    ldc.delete("ou="+_tfDomainName.getText() + ", o=netscaperoot");
                    ldc.delete("ou=Gloabl Preferences, ou="+
                            _tfDomainName.getText() + ", o=netscaperoot");
                } catch (LDAPException e1) {
                }
                break;
            }

            super.okInvoked();
            return;
        }

        SuiOptionPane.showMessageDialog(null,
                _resource.getString(sNewDomain, "FailToCreate"),
                _resource.getString("error","title"),
                SuiOptionPane.ERROR_MESSAGE);
        ModalDialogUtil.sleep();
    }
}

