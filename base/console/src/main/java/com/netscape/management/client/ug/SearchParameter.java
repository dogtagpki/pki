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

import java.util.Hashtable;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.nmclf.*;


/**
 * SearchParameter provides a component that can be used to prompt for
 * search criteria. The search criteria has the form attribute-condition-value.
 * The attribute can be selected from a combo box, as well as the condition
 * that the value is tested against. The value can be specified in a text
 * field.
 *
 * @see AdvancePanel
 */
public class SearchParameter extends JPanel {

    JComboBox _attributeName;
    JComboBox _condition;
    JTextField _filter;
    Hashtable _conditionLookup;
    ActionPanel _actionPanel;

    /**
     * Used to set the default focus on the search button whenever the _filter
     * gains focus.
     */
    private FocusAdapter _focusAdaptor = new FocusAdapter() {
                public void focusGained(FocusEvent e) {
                    if (e.getComponent() == _filter &&
                            _actionPanel != null) {
                        _actionPanel.setDefaultButton();
                    }
                }
            };


    /**
    * Constructor
    */
    public SearchParameter() {
        _actionPanel = null;

        PickerEditorResourceSet resource = new PickerEditorResourceSet();

        _attributeName = new JComboBox();
        _attributeName.getAccessibleContext().setAccessibleDescription(resource.getString("advance", "attrName"));
        _attributeName.setMaximumRowCount(5);
        int nChoice = Integer.parseInt(resource.getString("advance", "attrNchoice"));
        for (int i = 0; i < nChoice; i++) {
            _attributeName.addItem(resource.getString("advance", "attrChoice"+i));
        }

        _condition = new JComboBox();
        _condition.getAccessibleContext().setAccessibleDescription(resource.getString("advance", "condition"));
        _condition.setMaximumRowCount(5);
        _conditionLookup = new Hashtable();
        nChoice = Integer.parseInt(resource.getString("advance", "compareNchoice"));
        String conditionInfo;
        String internalReference;
        String displayedString;
        int commaIndex;
        for (int i = 0; i < nChoice; i++) {
            conditionInfo = resource.getString("advance", "compareChoice"+i);
            commaIndex = conditionInfo.indexOf(',');
            internalReference = conditionInfo.substring(0, commaIndex);
            displayedString = conditionInfo.substring(commaIndex + 1);
            _conditionLookup.put(internalReference, displayedString);
            _condition.addItem(displayedString);
        }

        _filter = new JTextField(8);
        _filter.getAccessibleContext().setAccessibleDescription(resource.getString("advance", "value"));
        _filter.addFocusListener(_focusAdaptor);

        setLayout(new GridBagLayout());
        GridBagUtil.constrain(this, _attributeName, 0, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(this, _condition, 1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(this, _filter, 2, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
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
        _actionPanel = ap;
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
        return _filter;
    }


    /**
      * Retrieves the selected attribute.
      *
      * @return  the selected attribute
      */
    public String getAttributeName() {
        return (String)_attributeName.getSelectedItem();
    }


    /**
      * Returns the selected condition.
      *
      * @return  the selected condition
      */
    public String getCondition() {
        return (String)_condition.getSelectedItem();
    }


    /**
      * Returns the display string for the selected condition. This is for i18n
     * requirement.
     *
     * @return  the display string for the selected condition
      */
    public String getCondition(String condition) {
        return (String)_conditionLookup.get(condition);
    }


    /**
     * Returns the selected value.
     *
     * @return  the selected value
     */
    public String getTextValue() {
        return _filter.getText();
    }
}
