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
import java.awt.event.*;
import java.net.*;

import javax.swing.*;
import netscape.ldap.*;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * DynamicQueryDlg allows the administrator to build and test LDAP queries.
 * The results can be checked to determine whether the LDAP query is
 * suitable to use as a group membership criterium.
 *
 * @see ResEditorDynamicGpMembers
 * @see LdapQueryBuilderDialog
 * @see SearchResultPanel
 */
public class DynamicQueryDlg extends AbstractDialog {

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    JTextField _url;
    JButton _constructButton;
    JButton _testButton;
    SearchResultPanel _resultPanel;
    String _resultQuery;
    ConsoleInfo _consoleInfo;
    Help _helpSession;

    /**
     * Used to set the default focus on _searchButton whenever the _queryField
     * gains focus.
     */
    FocusAdapter _focusAdaptor = new FocusAdapter() {
                public void focusGained(FocusEvent e) {
                    if (e.getComponent() == _url) {
                        _testButton.getRootPane().setDefaultButton(
                                _testButton);
                    }
                }
            };

    /**
     * Used to handle action events for buttons.
     */
    ActionListener _actionListener = new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    Object src = e.getSource();
                    if (src == _constructButton) {
                        LdapQueryBuilderDialog lqbd =
                                new LdapQueryBuilderDialog(
                                _resource.getString("dynamicQueryConstructor",
                                "title"), _consoleInfo);
                        lqbd.show();
                        if (lqbd.isCancel() == false) {
                            _url.setText(lqbd.getQueryString());
                        }
                    } else if (src == _testButton) {
                        Debug.println("DynamicQueryDlg:"+_url.getText());
                        _resultPanel.removeAllElements();

                        LDAPUrl ldapURL = getLDAPUrl();
                        if (ldapURL == null) {
                            return; // invalid url
                        }

                        LDAPConnection ldc =
                                _consoleInfo.getUserLDAPConnection();
                        if (ldc.isConnected() == false) {
                            Debug.println("DynamicQueryDlg.actionPerformed: not connected");
                            return;
                        }
                        Debug.println("DynamicQueryDlg:"+
                                ldapURL.getHost() + " "+
                                ldapURL.getPort());
                        _resultPanel.doSearch(ldc, ldapURL);
                    }
                }
            };


    /**
     * Constructor creates the dialog
     *
     * @param consoleInfo   session info
     * @param parent        the parent JFrame
     * @param modal         whether the dialog should be modal
     * @param initialValue  the LDAP query string to place in the editable field
     */
    public DynamicQueryDlg(ConsoleInfo consoleInfo, JFrame parent,
            boolean modal, String initialValue) {
        super(parent, "", modal, OK | CANCEL | HELP, HORIZONTAL_BUTTONS);
        _helpSession = new Help(_resource);

        setTitle(_resource.getString("dynamicQuery","title"));

        _resultQuery = "";
        _consoleInfo = consoleInfo;

        JLabel label = new JLabel(_resource.getString("dynamicQuery", "label"));

        _url = new JTextField();
        label.setLabelFor(label);
        _url.setText(initialValue);
        _url.addFocusListener(_focusAdaptor);

        _constructButton =
                new JButton(_resource.getString("dynamicQuery", "constructQuery"));
        _constructButton.setToolTipText(_resource.getString("dynamicQuery", "constructQuery_tt"));
        _constructButton.addActionListener(_actionListener);
        _testButton = new JButton(_resource.getString("dynamicQuery", "testQuery"));
        _testButton.setToolTipText(_resource.getString("dynamicQuery", "testQuery_tt"));
        _testButton.addActionListener(_actionListener);
        JButtonFactory.resizeGroup(_constructButton, _testButton);
        JLabel blankLabel = new JLabel(""); // Provide separation between the buttons

        JLabel resultLabel =
                new JLabel(_resource.getString("dynamicQuery", "resultLabel"));
        _resultPanel = new SearchResultPanel(_actionListener);
        resultLabel.setLabelFor(_resultPanel);

        JPanel p = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(p, label, 0, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(p, _url, 0, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(p, _testButton, 0, 2, 1, 1, 0, 0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p, _constructButton, 1, 2, 1, 1, 0, 0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(p, resultLabel, 0, 3,
                GridBagConstraints.REMAINDER, 1, 1.0, 0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p, _resultPanel, 0, 4,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        setComponent(p);

        setMinimumSize(600, 350);
        setSize(600, 350);
    }

    /**
     * Read and evaluate ldap url.
     * @return ldap url or null if invalid url
     */
    private LDAPUrl getLDAPUrl() {
        String url = _url.getText();
        LDAPUrl ldapurl = null;
        String errmsg = null;
        
        try {
            ldapurl = new LDAPUrl(LDAPUrl.decode(url));
        }
        catch (MalformedURLException ex) {
            errmsg = _resource.getString("dynamicQuery", "errortext");
        }        
        
        if (errmsg != null) {
            JOptionPane.showMessageDialog(
                UtilConsoleGlobals.getActivatedFrame(),
                errmsg, _resource.getString("dynamicQuery", "errortitle"),
                JOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();
            _url.requestFocus();
            _url.selectAll();
        }
        return ldapurl;
    }
        
    /**
      * Handle the action event to accept the LDAP query.
      */
    public void okInvoked() {
        
        if (getLDAPUrl() == null) {
            return; // invalid url
        }
        _resultQuery = _url.getText();
        super.okInvoked();
    }


    /**
      * Display help information specific to this dialog.
      */
    public void helpInvoked() {
        _helpSession.contextHelp("ug","ResEditorDynamicGpMembersAdd");
    }


    /**
      * Return the selected LDAP query string to the caller.
      *
      * @return  the selected LDAP query string
      */
    public String getResult() {
        return _resultQuery;
    }
}
