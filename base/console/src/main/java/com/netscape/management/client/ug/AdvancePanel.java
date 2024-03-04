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

import java.awt.event.*;
import java.util.*;
import java.awt.*;

import javax.swing.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * AdvancePanel provides a more functional interface for narrowing down
 * searches. Searches can be limited to those objects matching a single
 * attribute or a series of attributes (up to 5).
 *
 * AdvancePanel implements the IStandardResPickerPlugin and thus can be
 * plugged in to the ResourcePickerDlg. It serves as an example of how
 * plug-ins can be developed for the ResourcePickerDlg.
 *
 * @see BasicPanel
 * @see ActionPanel
 * @see ResourcePickerDlg
 * @see SearchParameter
 */
public class AdvancePanel extends JPanel implements ActionListener,
IStandardResPickerPlugin {

    private static final int MAX_SEARCH_PARAMETERS = 5;

    // Used to lookup the selected object class types in _objectClassLookup
    public  static final String KEY_USERS = "Users";
    public  static final String KEY_GROUPS = "Groups";
    public  static final String KEY_USERS_GROUPS = "Users and Groups";
    public  static final String KEY_ADMINISTRATORS = "Administrators";
    private static final String KEY_SERVERS = "Servers"; // Currently not used

    // Used to lookup the selected condition types in SearchParameter
    private static final String KEY_CONTAINS = "contains";
    private static final String KEY_EQUALS = "equals";
    private static final String KEY_NOT_EQUALS = "does not equal";

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();

    JComboBox _puSearchGroup;
    Hashtable _objectClassLookup;

    JButton bMore;
    JButton bFewer;
    int _iDisplayCount;
    JLabel _label1;
    JLabel _label2;
    JLabel[]_additionalConditionLabels;
    GridBagLayout _layout;

    SearchParameter _p[];

    ConsoleInfo _ConsoleInfo;
    AttributeSearchFilter[]_AttributeSearchFilter;


    /**
     * Constructor creates a new AdvancePanel object.
     */
    public AdvancePanel() {
        super();

        _iDisplayCount = 1;

        _label1 = new JLabel(_resource.getString("search", "AdvancedLabel"),
                SwingConstants.RIGHT);
        _label2 =
                new JLabel(_resource.getString("advance", "conditionLabel"),
                SwingConstants.RIGHT);
        _puSearchGroup = new JComboBox();
        _label1.setLabelFor(_puSearchGroup);
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

        _additionalConditionLabels = new JLabel[MAX_SEARCH_PARAMETERS - 1];
        _p = new SearchParameter[MAX_SEARCH_PARAMETERS];
        for (int i = 0; i < MAX_SEARCH_PARAMETERS; i++) {
            _p[i] = new SearchParameter();
            if (i < MAX_SEARCH_PARAMETERS - 1) {
                _additionalConditionLabels[i] = new JLabel(
                        _resource.getString("advance", "additionalConditionLabel"),
                        SwingConstants.RIGHT);
            }
        }

        bMore = new JButton(_resource.getString("advance", "moreButton"));
        bMore.setToolTipText(_resource.getString("advance", "more_tt"));
        bMore.addActionListener(this);

        bFewer = new JButton(_resource.getString("advance", "fewerButton"));
        bFewer.setToolTipText(_resource.getString("advance", "fewer_tt"));
        bFewer.addActionListener(this);
        bFewer.setEnabled(false);

        resetLayout();
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
    }


    /**
      * Used to satisfy usability requirement to set the default focus on the
      * search button of the ActionPanel when any one of the type-in fields is
      * being typed into. This allows the carriage return in one of these type-in
      * fields to start the search.
      *
      * @param ap  the ActionPanel containing the search button
      */
    public void setActionPanel(ActionPanel ap) {
        for (int i = 0; i < _p.length; i++) {
            _p[i].setActionPanel(ap);
        }
    }


    /**
      * Used to satisfy usability requirement to set the initial focus to the first
      * type-in field. This focus is set when the panel is first displayed, which
      * allows users to immediately type in to the field without first having to
      * click in the field.
      *
      * @return  the component which should get the initial focus
      */
    public JComponent getFocusComponent() {
        return _p[0].getFocusComponent();
    }


    /**
      * Implements the IResourcePickerPlugin interface. Returns the unique ID for
      * this plugin.
      *
      * @return  the unique ID for this plugin
      */
    public String getID() {
        return ResourcePickerDlg.ADVANCE_SEARCH_PANEL;
    }


    /**
      * Implements the IResourcePickerPlugin interface. Returns the string that should
      * be displayed as the method button in the ActionPanel.
      *
      * @return  the method button text label for this plugin
      */
    public String getDisplayName() {
        return _resource.getString("search","AdvancedButton");
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
      * Redo the layout of components when the dialog grows (More) or shrinks (Fewer).
      */
    void resetLayout() {
        removeAll();
        setLayout(new GridBagLayout());

        GridBagUtil.constrain(this, _label1, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 48, 0, 0);

        GridBagUtil.constrain(this, _puSearchGroup, 1, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(this, _label2, 0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0, 0);

        // There is at least one of these.
        GridBagUtil.constrain(this, _p[0], 1, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);

        for (int i = 1; i < _iDisplayCount; i++) {
            _additionalConditionLabels[i -1].setLabelFor(_p[i]);
            GridBagUtil.constrain(this,
                    _additionalConditionLabels[i - 1], 0, i + 1, 1, 1,
                    0.0, 0.0, GridBagConstraints.WEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE, 0, 0, 0);

            GridBagUtil.constrain(this, _p[i], 1, i + 1,
                    GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                    GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);
        }

        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JPanel innerPanel = new JPanel(
                new GridLayout(1, 2, SuiLookAndFeel.COMPONENT_SPACE, 0));
        innerPanel.add(bMore);
        innerPanel.add(bFewer);
        panel.add(innerPanel);
        GridBagUtil.constrain(this, panel, 1, _iDisplayCount + 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.SOUTH, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);

        doLayout();
    }


    /**
      * Implements the ActionListener interface. Handle events generated by the
      * More and Fewer buttons.
      *
      * @param e  the action event
      */
    public void actionPerformed(ActionEvent e) {
        int delta = 0;
        if (e.getSource().equals(bMore)) {
            _iDisplayCount++;
            if (_iDisplayCount == MAX_SEARCH_PARAMETERS) {
                bMore.setEnabled(false);
            }
            bFewer.setEnabled(true);
            resetLayout();
            delta = _p[0].getFocusComponent().getHeight() +
                    SuiLookAndFeel.COMPONENT_SPACE;
            setSize(getSize().width, getSize().height + delta);
            resizeParent(delta);
        } else if (e.getSource().equals(bFewer)) {
            _iDisplayCount--;
            if (_iDisplayCount == 1) {
                bFewer.setEnabled(false);
            }
            bMore.setEnabled(true);
            resetLayout();
            delta = _p[0].getFocusComponent().getHeight() +
                    SuiLookAndFeel.COMPONENT_SPACE;
            setSize(getSize().width, getSize().height - delta);
            resizeParent(-delta);
        } else {
            validate();
        }
    }


    /**
      * Resizes the parent dialog to actually grow or shrink.
      *
      * @param delta  the amount to resize the parent dialog by
      */
    private void resizeParent(int delta) {
        Component parent = getParent();
        while ((parent != null) && !(parent instanceof ResourcePickerDlg)) {
            parent = parent.getParent();
        }
        if (parent != null) {
            Dimension size = parent.getSize();
            parent.setSize(size.width, size.height + delta);
            ((ResourcePickerDlg) parent).validate();
        }
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
        String sFilter = "";
        String sReturn = "";
        String sli = (String)_puSearchGroup.getSelectedItem();

        for (int i = 0; i < _iDisplayCount; i++) {
            SearchParameter param = _p[i];

            String sClause = "";
            String sName = param.getAttributeName();
            String sCondition = param.getCondition();
            String sValue = param.getTextValue();

            if (sValue == null || sValue.equals("") == true) {
                continue;
            }

            if (sCondition.equals(param.getCondition(KEY_CONTAINS))) {
                if ((sValue == "") || (sValue.equals("*"))) {
                    sClause = "(" + sName + "=*)";
                } else if ((sValue.charAt(0) == '*') ||
                        (sValue.charAt(sValue.length() - 1) == '*')) {
                    sClause = "(" + sName + "=" + sValue + ")";
                } else {
                    sClause = "(" + sName + "=*" + sValue + "*)";
                }
            } else if (sCondition.equals(param.getCondition(KEY_EQUALS))) {
                sClause = "(" + sName + "=" + sValue + ")";
            } else if ( sCondition.equals(
                    param.getCondition(KEY_NOT_EQUALS))) {
                sClause = "(!(" + sName + "=" + sValue + "))";
            }

            if (i != 0) {
                sFilter = "(&" + sClause + sFilter + ")";
            } else {
                sFilter = sClause;
            }
        }

        if (sFilter.equals("")) {
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
            if (sli.equals(_objectClassLookup.get(KEY_USERS))) {
                sReturn = "(&(objectclass=person)" + sFilter + ")";
            } else if (sli.equals(_objectClassLookup.get(KEY_ADMINISTRATORS))) {
                sReturn = "(&(objectclass=person)" + sFilter + ")";
            } else if (sli.equals(_objectClassLookup.get(KEY_GROUPS))) {
                sReturn = "(&(objectclass=groupofuniquenames)" +
                        sFilter + ")";
            } else if (
                    sli.equals(_objectClassLookup.get(KEY_USERS_GROUPS))) {
                sReturn =
                        "(&(|(objectclass=person)(objectclass=groupofuniquenames))" +
                        sFilter + ")";
            } else if (sli.equals(_objectClassLookup.get(KEY_SERVERS))) {
                sReturn = "(&(objectclass=netscapeserver)" + sFilter + ")";
            }
        }
        Debug.println("Advanced Search: " + sReturn);
        return sReturn;
    }


    /**
      * Implements the IResourcePickerPlugin interface. Shows the help specific
      * to this plugin.
      */
    public void help() {
        Help help = new Help(_resource);
        help.contextHelp("ug","AdvancedSearch");
    }
}
