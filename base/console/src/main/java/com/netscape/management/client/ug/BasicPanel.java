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
import java.util.Hashtable;

import javax.swing.*;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.util.*;


/**
 * BasicPanel provides a simple interface for searching users and groups.
 * The user just needs to type a string to query. The picker then tries
 * to best match the query string to an entry's common name or user ID.
 *
 * BasicPanel implements the IStandardResPickerPlugin and thus can be
 * plugged in to the ResourcePickerDlg. It serves as an example of how
 * plug-ins can be developed for the ResourcePickerDlg.
 *
 * @see AdvancePanel
 * @see ActionPanel
 * @see ResourcePickerDlg
 * @see SearchParameter
 */
public class BasicPanel extends JPanel implements IStandardResPickerPlugin {

    // Used to lookup the selected object class types in _objectClassLookup
    private static final String KEY_USERS = "Users";
    private static final String KEY_GROUPS = "Groups";
    private static final String KEY_USERS_GROUPS = "Users and Groups";
    public  static final String KEY_ADMINISTRATORS = "Administrators";
    private static final String KEY_SERVERS = "Servers"; // Currently not used

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();

    JTextField _queryField;
    JComboBox _puSearchGroup;
    Hashtable _objectClassLookup;
    ActionPanel _actionPanel;

    ConsoleInfo _ConsoleInfo;
    AttributeSearchFilter[]_AttributeSearchFilter;
    String _sUniqueAttribute;

    /**
     * Used to set the default focus on the search button whenever the _queryField
     * gains focus.
     */
    private FocusAdapter _focusAdaptor = new FocusAdapter() {
                public void focusGained(FocusEvent e) {
                    if (e.getComponent() == _queryField &&
                            _actionPanel != null) {
                        _actionPanel.setDefaultButton();
                    }
                }
            };


    /**
     * Constructor creates a new BasicPanel object.
     */
    public BasicPanel() {
        _actionPanel = null;
        _sUniqueAttribute = new String("uid");

        JLabel label1 =
                new JLabel(_resource.getString("search", "BasicLabel"),
                SwingConstants.RIGHT);
        JLabel label2 = new JLabel(_resource.getString("basic", "forLabel"),
                SwingConstants.RIGHT);
        _queryField = new JTextField();
        label2.setLabelFor(_queryField);
        _queryField.addFocusListener(_focusAdaptor);
        _puSearchGroup = new JComboBox();
        label1.setLabelFor(_puSearchGroup);
        _objectClassLookup = new Hashtable();

        int nChoice = Integer.parseInt(_resource.getString("search", "Nchoice"));
        String objectClassInfo;
        String internalReference;
        String displayedString;
        int commaIndex;
        for (int i = 0; i < nChoice; i++) {
            objectClassInfo = _resource.getString("search", "Choice"+i);
            commaIndex = objectClassInfo.indexOf(',');
            internalReference = objectClassInfo.substring(0, commaIndex);
            displayedString = objectClassInfo.substring(commaIndex + 1);
            _objectClassLookup.put(internalReference, displayedString);
            _puSearchGroup.addItem(displayedString);
        }
        _puSearchGroup.setSelectedItem(
                _objectClassLookup.get(KEY_USERS));

        JLabel blankLabel = new JLabel("");

        setLayout(new GridBagLayout());
        GridBagUtil.constrain(this, label1, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 48, 0, 0);
        GridBagUtil.constrain(this, _puSearchGroup, 1, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(this, label2, 0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0, 0);
        GridBagUtil.constrain(this, _queryField, 1, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(this, blankLabel, 0, 2,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                0, 0, 0);
    }

   /**
    * Enable search of Configuration Administrators
    */
    public void enableAdminSearch() {
        String internalReference = KEY_ADMINISTRATORS;
        String displayedString = _resource.getString("search", "ChoiceAdmin");
        _objectClassLookup.put(internalReference, displayedString);
        _puSearchGroup.addItem(displayedString);
    }

    /**
      * Implements IResourcePickerPlugin interface. Initializes object with the
      * session information.
      *
      * @param info  the session information
      */
    public void initialize(ConsoleInfo info) {
        _ConsoleInfo = info;
        _sUniqueAttribute = ResourceEditor.getUniqueAttribute();
    }


    /**
      * Used to satisfy usability requirement to set the default focus on the
      * search button of the ActionPanel when the type-in fields is being typed
      * into. This allows the carriage return in the type-in field to start the
      * search.
      *
      * @param ap  the ActionPanel containing the search button
      */
    public void setActionPanel(ActionPanel ap) {
        _actionPanel = ap;
    }


    /**
      * Used to satisfy usability requirement to set the initial focus to the
      * type-in field. This focus is set when the panel is first displayed, which
      * allows users to immediately type in to the field without first having to
      * click in the field.
      *
      * @return  the component which should get the initial focus
      */
    public JComponent getFocusComponent() {
        return _queryField;
    }


    /**
      * Implements the IResourcePickerPlugin interface. Returns the unique ID for
      * this plugin.
      *
      * @return  the unique ID for this plugin
      */
    public String getID() {
        return ResourcePickerDlg.BASIC_SEARCH_PANEL;
    }


    /**
      * Implements the IResourcePickerPlugin interface. Returns the string that should
      * be displayed as the method button in the ActionPanel.
      *
      * @return  the method button text label for this plugin
      */
    public String getDisplayName() {
        return _resource.getString("search", "BasicButton");
    }


    /**
      * Implements the IResourcePickerPlugin interface. Returns the UI component to
      * display when the plugin is selected. For this plugin, this method returns the
      * plugin itself.
      *
      * @return  the UI component to display
      */
    public Component getSearchUI() {
        return this;
    }


    /**
      * Sets the display attributes.
      *
      * @param  arFilter  an array of AttributeSearchFilter objects
      */
    public void setDisplayAttribute(AttributeSearchFilter arFilter[]) {
        _AttributeSearchFilter = arFilter;
    }


    /**
      * Implements the IStandardResPickerPlugin interface. Gets the display attributes.
      *
      * @return  an array of AttributeSearchFilter objects
      */
    public AttributeSearchFilter[] getDisplayAttribute() {
        return _AttributeSearchFilter;
    }

    /**
     * Returns the type of the selected search object
     * @return  type of search object (user, group, administrator)
     */
    public String getSearchType() {
        return (String)_puSearchGroup.getSelectedItem();
    }


    /**
      * Implements the IResourcePickerPlugin interface. Returns the filter string
      * for the query specified using this plugin.
      *
      * @return  the filter string for the query
      */
    public String getFilterString() {
        String sFilter = _queryField.getText();
        String sReturn = "";
        String sli = (String)_puSearchGroup.getSelectedItem();

        if (sFilter.equals("") || sFilter.equals("*")) {
            if (sli.equals(_objectClassLookup.get(KEY_USERS))) {
                sReturn = "(objectclass=person)";
            } else if (sli.equals(_objectClassLookup.get(KEY_ADMINISTRATORS))) {
                sReturn = "(objectclass=person)";
            } else if (sli.equals(_objectClassLookup.get(KEY_GROUPS))) {
                sReturn = "(objectclass=groupofuniquenames)";
            } else if (
                    sli.equals(_objectClassLookup.get(KEY_USERS_GROUPS))) {
                sReturn = "(|(objectclass=person)(objectclass=groupofuniquenames))";
            } else if (sli.equals(_objectClassLookup.get(KEY_SERVERS))) {
                sReturn = "(objectclass=netscapeserver)";
            }
        } else {
            if (sFilter.indexOf('*') == -1) {
                sFilter = "*" + sFilter + "*";
            }

            if (_sUniqueAttribute.equals("cn")) {
                if (sli.equals(_objectClassLookup.get(KEY_USERS))) {
                    sReturn = "(&(objectclass=person)(cn=" + sFilter + "))";
                } else if (sli.equals(_objectClassLookup.get(KEY_ADMINISTRATORS))) {
                    sReturn = "(&(objectclass=person)(cn=" + sFilter + "))";
                } else if (
                        sli.equals(_objectClassLookup.get(KEY_GROUPS))) {
                    sReturn = "(&(objectclass=groupofuniquenames)(cn=" +
                            sFilter + "))";
                } else if ( sli.equals(
                        _objectClassLookup.get(KEY_USERS_GROUPS))) {
                    sReturn = "(|(&(objectclass=person)(cn=" + sFilter +
                            "))(&(objectclass=groupofuniquenames)(cn=" +
                            sFilter + ")))";
                } else if (
                        sli.equals(_objectClassLookup.get(KEY_SERVERS))) {
                    sReturn = "(&(objectclass=netscapeserver)(cn=" +
                            sFilter + "))";
                }
            } else if (_sUniqueAttribute.equals("uid")) {
                // Do not perform the substring search on UID, unless user specifically entered it.
                String orig = _queryField.getText();
                if (sli.equals(_objectClassLookup.get(KEY_USERS))) {
                    sReturn = "(|(&(objectclass=person)(cn=" + sFilter +
                            "))(&(objectclass=person)(uid=" + orig + ")))";
                } else if (sli.equals(_objectClassLookup.get(KEY_ADMINISTRATORS))) {
                    sReturn = "(|(&(objectclass=person)(cn=" + sFilter +
                            "))(&(objectclass=person)(uid=" + orig + ")))";
                } else if (
                        sli.equals(_objectClassLookup.get(KEY_GROUPS))) {
                    sReturn = "(&(objectclass=groupofuniquenames)(cn=" +
                            sFilter + "))";
                } else if ( sli.equals(
                        _objectClassLookup.get(KEY_USERS_GROUPS))) {
                    sReturn = "(|(&(objectclass=person)(cn=" + sFilter +
                            "))(&(objectclass=person)(uid=" + orig +
                            "))(&(objectclass=groupofuniquenames)(cn=" +
                            sFilter + ")))";
                } else if (
                        sli.equals(_objectClassLookup.get(KEY_SERVERS))) {
                    sReturn = "(&(objectclass=netscapeserver)(cn=" +
                            sFilter + "))";
                }
            } else {
                if (sli.equals(_objectClassLookup.get(KEY_USERS))) {
                    sReturn = "(|(&(objectclass=person)(cn=" + sFilter +
                            "))(&(objectclass=person)(" +
                            _sUniqueAttribute + "=" + sFilter + ")))";
                } else if (sli.equals(_objectClassLookup.get(KEY_ADMINISTRATORS))) {
                    sReturn = "(|(&(objectclass=person)(cn=" + sFilter +
                            "))(&(objectclass=person)(" +
                            _sUniqueAttribute + "=" + sFilter + ")))";
                } else if (
                        sli.equals(_objectClassLookup.get(KEY_GROUPS))) {
                    sReturn = "(|(&(objectclass=groupofuniquenames)(cn=" +
                            sFilter +
                            "))(&(objectclass=groupofuniquenames)(" +
                            _sUniqueAttribute + "=" + sFilter + ")))";
                } else if ( sli.equals(
                        _objectClassLookup.get(KEY_USERS_GROUPS))) {
                    sReturn = "(|(&(objectclass=person)(cn=" + sFilter +
                            "))(&(objectclass=person)(" +
                            _sUniqueAttribute + "=" + sFilter +
                            "))(&(objectclass=groupofuniquenames)(cn=" +
                            sFilter +
                            "))(&(objectclass=groupofuniquenames)(" +
                            _sUniqueAttribute + "=" + sFilter + ")))";
                } else if (
                        sli.equals(_objectClassLookup.get(KEY_SERVERS))) {
                    sReturn = "(|(&(objectclass=netscapeserver)(cn=" +
                            sFilter + "))(&(objectclass=netscapeserver)(" +
                            _sUniqueAttribute + "=" + sFilter + ")))";
                }
            }
        }
        Debug.println("Basic Search: " + sReturn);
        return sReturn;
    }


    /**
      * Implements the IResourcePickerPlugin interface. Shows the help specific
      * to this plugin.
      */
    public void help() {
        Help help = new Help(_resource);
        help.contextHelp("ug","BasicSearch");
    }
}
