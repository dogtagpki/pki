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
import java.util.*;

import javax.swing.*;
import javax.swing.border.*;

import com.netscape.management.client.util.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.nmclf.*;
import netscape.ldap.*;


/**
 * LdapQueryBuilderDialog can be used to define an LDAP URL query string in
 * the form of "protocol://server:port/baseDN?attribute?scope?query".
 * This dialog makes it easier for users to build the correctly formatted URL.
 *
 * @see DynamicQueryDlg
 */
public class LdapQueryBuilderDialog extends AbstractModalDialog {

    static final int MAX_CRITERIA_COUNT = 5;
    static final String RESOURCE_STRING_PREFIX = "dynamicQueryConstructor";

    ResourceSet _resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");
    Help _helpSession; // For invoking help.
    int _criteriaCount;
    LdapCriteria[]_criteria;
    private int _startLine = 55;
    String _queryString;
    ConsoleInfo _consoleInfo;

    JButton _moreButton;
    JButton _fewerButton;
    JComboBox _searchScope;
    JComboBox _userOrGroup;
    JLabel _host;
    JLabel _port;
    JTextField _baseDN;
    JPanel _criteriaPanel;
    JPanel _buttonPanel;

    /**
     * Used to handle action events.
     */
    ActionListener _actionListener = new ActionListener() {
                /**
                  * Handles action event generated when a button is pressed.
                  *
                  * @param e  the action event
                  */
                public void actionPerformed(ActionEvent e) {
                    Object src = e.getSource();
                    if (src == _moreButton) {
                        LdapQueryBuilderDialog.this.moreInvoked();
                    } else if (src == _fewerButton) {
                        LdapQueryBuilderDialog.this.fewerInvoked();
                    }
                }
            };


    /**
     * Create an LdapQueryBuilderDialog object.
     *
     * @param ci  session information
     */
    public LdapQueryBuilderDialog(ConsoleInfo ci) {
        super(null);
        setTitle(_resource.getString(RESOURCE_STRING_PREFIX, "title"));

        _consoleInfo = ci;
        _criteriaCount = 0;
        _criteria = new LdapCriteria[MAX_CRITERIA_COUNT];
        _helpSession = new Help(_resource);

        _moreButton = new JButton(
                _resource.getString(RESOURCE_STRING_PREFIX, "moreButton"));
        _moreButton.setToolTipText(_resource.getString(RESOURCE_STRING_PREFIX, "more_tt"));
        _moreButton.addActionListener(_actionListener);
        _fewerButton = new JButton(
                _resource.getString(RESOURCE_STRING_PREFIX, "fewerButton"));
        _fewerButton.setToolTipText(_resource.getString(RESOURCE_STRING_PREFIX, "fewer_tt"));
        _fewerButton.addActionListener(_actionListener);
        JButtonFactory.resizeGroup(_moreButton, _fewerButton);
        _fewerButton.setEnabled(false); // Initially disabled.

        _searchScope = new JComboBox();
        populateComboBox(_searchScope, RESOURCE_STRING_PREFIX, "searchScopeCount",
                "searchScope");
        _searchScope.setSelectedIndex(2);

        _userOrGroup = new JComboBox();
        populateComboBox(_userOrGroup, RESOURCE_STRING_PREFIX, "searchClassCount",
                "searchClass");
        _userOrGroup.setSelectedIndex(2);

        JLabel hostLabel = new JLabel(
                _resource.getString(RESOURCE_STRING_PREFIX, "hostLabel"));
        JLabel portLabel = new JLabel(
                _resource.getString(RESOURCE_STRING_PREFIX, "portLabel"));
        JLabel baseDNLabel = new JLabel(
                _resource.getString(RESOURCE_STRING_PREFIX, "baseDNLabel"));
        JLabel searchLabel = new JLabel(
                _resource.getString(RESOURCE_STRING_PREFIX,
                "searchLabel"), JLabel.RIGHT);
        searchLabel.setLabelFor(_searchScope);
        JLabel searchForLabel = new JLabel(
                _resource.getString(RESOURCE_STRING_PREFIX, "searchForLabel"));
        searchForLabel.setLabelFor(_userOrGroup);
        JLabel blankLabel = new JLabel("");

        _host = new JLabel();
        hostLabel.setLabelFor(_host);
        _host.setBorder(new BevelBorder(BevelBorder.LOWERED));
        _host.setText(_consoleInfo.getUserHost());
        _port = new JLabel();
        portLabel.setLabelFor(_port);
        _port.setBorder(new BevelBorder(BevelBorder.LOWERED));
        _port.setText(Integer.toString(_consoleInfo.getUserPort()));
        _baseDN = new JTextField();
        baseDNLabel.setLabelFor(_baseDN);
        _baseDN.setText(_consoleInfo.getUserBaseDN());

        JPanel hostPanel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(hostPanel, hostLabel, 0, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                0, 0, 0, 0);
        GridBagUtil.constrain(hostPanel, _host, 1, 0, 1, 1, 0.5, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(hostPanel, portLabel, 2, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                0, SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(hostPanel, _port, 3, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.NONE, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(hostPanel, baseDNLabel, 4, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                0, SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(hostPanel, _baseDN, 5, 0, 1, 1, 0.5, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);

        JPanel searchPanel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(searchPanel, searchLabel, 0, 0, 1, 1,
                0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.NONE, 0, 0, 0, 0);
        GridBagUtil.constrain(searchPanel, _searchScope, 1, 0, 1, 1,
                0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.NONE, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(searchPanel, searchForLabel, 2, 0, 1, 1,
                0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.NONE, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(searchPanel, _userOrGroup, 3, 0, 1, 1,
                0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.NONE, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);

        _criteriaPanel = new JPanel(new GridBagLayout());
        _buttonPanel = new JPanel( new FlowLayout(FlowLayout.LEFT,
                SuiLookAndFeel.COMPONENT_SPACE, 0));
        _buttonPanel.add(_moreButton);
        _buttonPanel.add(_fewerButton);

        Container c = getContentPane();
        c.setLayout(new GridBagLayout());
        GridBagUtil.constrain(c, hostPanel, 0, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        GridBagUtil.constrain(c, searchPanel, 0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.NONE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0, 0);
        GridBagUtil.constrain(c, _criteriaPanel, 0, 2, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0, 0);
        GridBagUtil.constrain(c, blankLabel, 0, 3, 1, 1, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0, 0);

        addRow();
    }


    /**
      * Create an LdapQueryBuilderDialog with the specified title.
      *
      * @param title  the dialog title
      * @param ci     session information
      */
    public LdapQueryBuilderDialog(String title, ConsoleInfo ci) {
        this(ci);
        setTitle(title);
    }


    /**
      * Initializes the LdapQueryBuilderDialog object.
      */
    public void initialize() {
        _queryString = "";
    }


    /**
      * Returns the selected query string.
      *
      * @return the selected query string
      */
    public String getQueryString() {
        return _queryString;
    }


    /**
      * Parses LDAP info in the form of <LDAPINFO> type: value </LDAPINFO>
      *
      * @param data  information to parse
      */
    public void parse(String data) {
        String strType;
        String strValue;
        int curindex;
        int strsize;

        curindex = data.indexOf("<LDAPINFO>");
        while (curindex != -1) {
            curindex = curindex + 10;
            strsize = data.indexOf(":",curindex) - curindex;
            strType = data.substring(curindex, curindex + strsize);
            curindex = curindex + strsize + 1; // 1 for the colon
            strsize = data.indexOf("</LDAPINFO>",curindex) - curindex;
            strValue = data.substring(curindex, curindex + strsize);
            strValue = strValue.trim();
            curindex = curindex + strsize + 11;
            if (strType.indexOf("BASEDN") != -1) {
                // base dn info:
                _baseDN.setText(strValue);
            }
            curindex = data.indexOf("<LDAPINFO>",curindex);
        }
    }


    /**
      * Creates the search URL.
      */
    private void createQueryString() {
        _queryString = ("ldap://" + _consoleInfo.getUserHost() + ":" +
                        _consoleInfo.getUserPort() + "/");
        _queryString += LDAPUrl.encode(_baseDN.getText());

        switch (_searchScope.getSelectedIndex()) {
        case 0: // Base DN only
            _queryString += "??base?";
            break;
        case 1: // One level below Base DN
            _queryString += "??one?";
            break;
        case 2: // All levels starting with Base DN
        default:
            _queryString += "??sub?";
            break;
        }

        String filter;
        switch (_userOrGroup.getSelectedIndex()) {
        case 0: // users only
            filter = "(&(objectclass=person)";
            break;
        case 1: // groups only
            filter = "(&(objectclass=groupofuniquenames)";
            break;
        case 2: // both users and groups
        default:
            filter = "(&(|(objectclass=person)(objectclass=groupofuniquenames))";
            break;
        }

        String value;
        for (int i = 0; i < _criteriaCount; i++) {
            if (_criteria[i]._condition.getSelectedIndex() == 3) {
                filter += "(!(";
            } else if (_criteria[i]._condition.getSelectedIndex() == 1) {
                filter += "(!(";
            } else {
                filter += "(";
            }

            filter +=
                    (String)(_criteria[i]._attribute.getSelectedItem());

            value = _criteria[i]._value.getText();
            if (value.length() == 0) {
                value = "*"; // Treat empty fields as match all
            }

            switch (_criteria[i]._condition.getSelectedIndex()) {
            case 0: // contains
                if (value.charAt(0) == '*')
                    filter += "=";
                else
                    filter += "=*";
                filter += value;
                if (value.charAt(value.length() - 1) == '*')
                    filter += ")";
                else
                    filter += "*)";
                break;
            case 1: // does not contain (see above)
                if (value.charAt(0) == '*')
                    filter += "=";
                else
                    filter += "=*";
                filter += value;
                if (value.charAt(value.length() - 1) == '*')
                    filter += "))";
                else
                    filter += "*))";
                break;
            case 2: // is
                filter += "=";
                filter += value;
                filter += ")";
                break;
            case 3: // is not (see above)
                filter += "=";
                filter += value;
                filter += "))";
                break;
            case 4: // begins with
                filter += "=";
                filter += value;
                if (value.charAt(value.length() - 1) == '*')
                    filter += ")";
                else
                    filter += "*)";
                break;
            case 5: // ends with
                if (value.charAt(0) == '*')
                    filter += "=";
                else
                    filter += "=*";
                filter += value;
                filter += ")";
                break;
            case 6: // sounds like
                filter += "~=";
                filter += value;
                filter += ")";
                break;
            default: // just in case treat like is
                filter += "=";
                filter += value;
                filter += ")";
                break;
            }
        }
        filter += ")";

        _queryString += LDAPUrl.encode(filter);
    }


    /**
      * Removes criteria row (when user selected "Fewer").
      */
    private void removeRow() {
        removeButtonRow();
        _criteriaCount--;
        _criteriaPanel.remove(_criteria[_criteriaCount]._value);
        _criteriaPanel.remove(_criteria[_criteriaCount]._condition);
        _criteriaPanel.remove(_criteria[_criteriaCount]._attribute);
        _criteriaPanel.remove(_criteria[_criteriaCount]._label);
        _criteria[_criteriaCount] = null;
        addButtonRow();
        _moreButton.setEnabled(true);

        Container c = getContentPane();
        c.doLayout();
        pack();
    }


    /**
      * Adds another criteria row (when user selected "More").
      */
    private void addRow() {
        removeButtonRow();
        _criteria[_criteriaCount] =
                new LdapCriteria(_consoleInfo, _resource, _criteriaCount);
        int topInset = 0;
        if (_criteriaCount > 0) {
            topInset = SuiLookAndFeel.COMPONENT_SPACE;
        }
        GridBagUtil.constrain(_criteriaPanel,
                _criteria[_criteriaCount]._label, 0, _criteriaCount,
                1, 1, 0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, topInset, 30, 0, 0);
        GridBagUtil.constrain(_criteriaPanel,
                _criteria[_criteriaCount]._attribute, 1,
                _criteriaCount, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.NONE,
                topInset, SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(_criteriaPanel,
                _criteria[_criteriaCount]._condition, 2,
                _criteriaCount, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.NONE,
                topInset, SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(_criteriaPanel,
                _criteria[_criteriaCount]._value, 3, _criteriaCount,
                1, 1, 1.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, topInset,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        _criteriaCount++;
        if (_criteriaCount > 1) {
            // There has to be at least 1 of these!
            _fewerButton.setEnabled(true);
        }
        addButtonRow();

        Container c = getContentPane();
        c.doLayout();
        pack();
    }


    /**
      * Removes row of buttons.
      */
    private void removeButtonRow() {
        if (_criteriaCount == 0) {
            return;
        }
        _criteriaPanel.remove(_buttonPanel);
    }


    /**
      * Adds row of buttons.
      */
    private void addButtonRow() {
        GridBagUtil.constrain(_criteriaPanel, _buttonPanel, 1,
                _criteriaCount, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.NONE,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0, 0);
    }


    /**
      * Handles event when user selected "OK".
      */
    protected void okInvoked() {
        createQueryString();
        super.okInvoked();
    }


    /**
      * Handles event when user selected "Help".
      */
    protected void helpInvoked() {
        _helpSession.contextHelp(RESOURCE_STRING_PREFIX, "help");
    }


    /**
      * Handles event when user selected "Fewer".
      */
    protected void fewerInvoked() {
        removeRow();
        if (_criteriaCount == 1) {
            _fewerButton.setEnabled(false);
        }
    }


    /**
      * Handles event when user selected "More".
      */
    protected void moreInvoked() {
        addRow();
        if (_criteriaCount == MAX_CRITERIA_COUNT) {
            _moreButton.setEnabled(false);
        }
    }


    /**
      * Populates the combo box with data from the property file.
      *
      * @param cb           the combo box to fill
      * @param prefix       the resource prefix
      * @param countSuffix  the resource count suffix
      * @param itemSuffix   the resource item suffix
      */
    private void populateComboBox(JComboBox cb, String prefix,
            String countSuffix, String itemSuffix) {
        int count = Integer.parseInt(
                _resource.getString(prefix, countSuffix));
        for (int i = 0; i < count; i++) {
            cb.addItem(_resource.getString(prefix, itemSuffix + i));
        }
    }
}


/**
  * Helper class to define the criteria input fields.
  */
class LdapCriteria {
    public JLabel _label;
    public JComboBox _attribute;
    public JComboBox _condition;
    public JTextField _value;

    static String[]_userGroupAttributes = null;


    /**
     * Creates an LdapCriteria object.
     *
     * @param ci         session information
     * @param resource   handle to the property file
     * @param rowNumber  the row where the criteria is being created
     */
    public LdapCriteria(ConsoleInfo ci, ResourceSet resource,
            int rowNumber) {

        if (_userGroupAttributes == null) {
            getUserGroupAttributes(ci);
        }
        _attribute = new JComboBox();
        if (_userGroupAttributes != null) {
            for (int i = 0; i < _userGroupAttributes.length; i++) {
                _attribute.addItem(_userGroupAttributes[i]);
            }
        }
        // The following prevents visible items from getting cut off with initial dialog size.
        _attribute.setMaximumRowCount(5);
        _attribute.setSelectedItem("cn");

        _condition = new JComboBox();
        populateComboBox(_condition, resource, "dynamicQueryConstructor",
                "conditionCount", "condition");
        _condition.setMaximumRowCount(5);

        _value = new JTextField();

        if (rowNumber == 0) {
            _label = new JLabel(
                    resource.getString("dynamicQueryConstructor",
                    "whereLabel"), JLabel.RIGHT);
        } else {
            _label = new JLabel(
                    resource.getString("dynamicQueryConstructor",
                    "andLabel"), JLabel.RIGHT);
        }
    }


    /**
      * Populates the combo box with data from the property file.
      *
      * @param cb           the combo box to fill
      * @param resource     handle to the property file
      * @param prefix       the resource prefix
      * @param countSuffix  the resource count suffix
      * @param itemSuffix   the resource item suffix
      */
    private void populateComboBox(JComboBox cb, ResourceSet resource,
            String prefix, String countSuffix, String itemSuffix) {
        int count =
                Integer.parseInt(resource.getString(prefix, countSuffix));
        for (int i = 0; i < count; i++) {
            cb.addItem(resource.getString(prefix, itemSuffix + i));
        }
    }


    /**
      * Dynamically retrieves the attributes for user and group object
      * classes using the LDAP schema.
      *
      * @param ci  session information
      */
    private void getUserGroupAttributes(ConsoleInfo ci) {
        LDAPSchema schema = null;
        LDAPConnection ldc = ci.getUserLDAPConnection();
        if ((ldc != null) && (ldc.isConnected())) {
            try {
                /* Get the schema from the Directory */
                schema = new LDAPSchema();
                schema.fetchSchema(ldc);
            } catch (LDAPException e) {
                schema = null;
            }
        }

        if (schema == null) {
            return;
        }

        Vector allAttributes = new Vector();

        Vector userObjectClasses =
                (Vector) ResourceEditor.getNewObjectClasses().get(
                ResourceEditor.KEY_NEW_USER_OBJECTCLASSES);
        Vector groupObjectClasses =
                (Vector) ResourceEditor.getNewObjectClasses().get(
                ResourceEditor.KEY_NEW_GROUP_OBJECTCLASSES);

        if (userObjectClasses == null || groupObjectClasses == null) {
            Debug.println("LdapQueryBuilderDialog: cannot get attributes since one or more objectclasses are null");
            return;
        }

        getAllAttributesFor(allAttributes, userObjectClasses, schema);
        getAllAttributesFor(allAttributes, groupObjectClasses, schema);

        if (allAttributes.size() > 0) {
            _userGroupAttributes = new String[allAttributes.size()];
            allAttributes.copyInto(_userGroupAttributes);
            sort(_userGroupAttributes, 0, _userGroupAttributes.length - 1);
        }
    }


    /**
      * Dynamically retrieves the attributes for user and group object
      * classes using the LDAP schema.
      *
      * @param result         the Vector to store results into
      * @param objectClasses  the attributes to retrieve for
      * @param schema         the LDAP schema information
      */
    private void getAllAttributesFor(Vector result,
            Vector objectClasses, LDAPSchema schema) {
        Enumeration objectClassEnum = objectClasses.elements();
        while (objectClassEnum.hasMoreElements()) {
            String ocName = (String) objectClassEnum.nextElement();
            LDAPObjectClassSchema objectClassEntry =
                    schema.getObjectClass(ocName);
            Enumeration enumReq = objectClassEntry.getRequiredAttributes();
            Enumeration enumAllow =
                    objectClassEntry.getOptionalAttributes();
            Object attr = null;
            while (enumReq.hasMoreElements()) {
                attr = (Object) enumReq.nextElement();
                if (((String) attr).equals("objectclass")) {
                    continue; // skip objectclass
                }
                if (result.indexOf(attr) == -1) {
                    result.addElement(attr); // Only add the attribute if not already present
                }
            }
            while (enumAllow.hasMoreElements()) {
                attr = (Object) enumAllow.nextElement();
                if (((String) attr).indexOf("binary") != -1) {
                    continue; // skip binaries
                }
                if (((String) attr).equals("aci")) {
                    continue; // skip
                }
                if (((String) attr).equals("jpegphoto")) {
                    continue; // skip
                }
                if (((String) attr).equals("userpassword")) {
                    continue; // skip
                }
                if (((String) attr).equals("audio")) {
                    continue; // skip
                }
                if (((String) attr).equals("seealso")) {
                    continue; // skip
                }
                if (result.indexOf(attr) == -1) {
                    result.addElement(attr); // Only add the attribute if not already present
                }
            }
        }
    }


    /**
      * Sort an array of strings in ascending order.
      *
      * @param array  an array of strings to sort
      * @param low    the first index to partially sort
      * @param high   the last index to partially sort
      */
    private void sort(String array[], int low, int high) {
        if (low >= high) {
            return;
        }

        String pivot = array[low];
        int slow = low - 1, shigh = high + 1;
        while (true) {
            do {
                shigh--;
            } while (isGreater(array[shigh], pivot))
                ;
            do {
                slow++;
            } while (isGreater(pivot, array[slow]))
                ;

            if (slow >= shigh) {
                break;
            }

            String temp = array[slow];
            array[slow] = array[shigh];
            array[shigh] = temp;
        }

        sort(array, low, shigh);
        sort(array, shigh + 1, high);
    }


    /**
      * Compares two strings.
      *
      * @param a  the first string
      * @param b  the second string
      * @return   true if the first string is greater; false otherwise
      */
    private boolean isGreater(String a, String b) {
        if (a.compareTo(b) <= 0) {
            return false;
        }
        return true;
    }
}
