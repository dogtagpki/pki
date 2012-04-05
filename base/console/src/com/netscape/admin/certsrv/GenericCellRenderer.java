// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.admin.certsrv;

import java.awt.*;
import java.lang.*;
import java.util.*;
import javax.swing.table.*;
import javax.swing.*;
import java.io.Serializable;
import com.netscape.certsrv.common.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.connection.*;

/**
 * Class that will render components correctly in table
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class GenericCellRenderer
    implements TableCellRenderer, Serializable
{
    /*==========================================================
     * variables
     *==========================================================*/
    protected JComponent component;
    private JPasswordField mPasswordField;
    private JLabel mLabel;
    private JCheckBox mCheckBox;
    private JComboBox mComboBox;
    protected ValueProperty value;
    static Color HIGHLIGHTCOLOR = new Color(0, 0, 128);
    static Color WHITECOLOR = Color.white;
    static Color BLACKCOLOR = Color.black;

    /*==========================================================
     * constructors
     *==========================================================*/

    public GenericCellRenderer() {
        value = new ValueProperty();
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    public void setToolTipText(String text) {
    	if (component instanceof JComponent)
    	    ((JComponent)component).setToolTipText(text);
    }

    public Component getComponent() {
        return component;
    }

    //==== Implementing TableCellRenderer =========
    public Component getTableCellRendererComponent(JTable table, Object value,
						   boolean isSelected,
						   boolean hasFocus,
						   int row, int column) {
        TableModel model = table.getModel();
        if(value == null) {

            value = model.getValueAt(row, column);
        }
        Vector v = (Vector)(((CMSContentTableModel)model).getObjectValueAt(row));
        this.value.setValue(value, v);
        component.setBackground(isSelected ? HIGHLIGHTCOLOR : WHITECOLOR);
        component.setForeground(isSelected ? WHITECOLOR : BLACKCOLOR);
        return component;
    }


    protected class ValueProperty implements Serializable {

        public void setValue(Object x, Vector v) {
            String type = (String)v.elementAt(0);
            if (type.equals(Constants.PASSWORDTYPE)) {
                if (mLabel == null) {
                    mLabel = new JLabel();
                    mLabel.setOpaque(true);
                    mLabel.setBorder(new EmptyBorder(1,CMSAdminUtil.COMPONENT_SPACE, 1, 2));
                    JPasswordField temp = new JPasswordField();
                    mLabel.setFont(temp.getFont());
                }
                component = mLabel;

                StringBuffer buf = new StringBuffer();
                for(int i=0; i< ((String)x).length(); i++)
                    buf.append("*");
                ((JLabel)component).setText(buf.toString());
            } else if (type.equals(Constants.TEXTTYPE)) {
                if (mLabel == null) {
                    mLabel = new JLabel();
                    mLabel.setOpaque(true);
                    mLabel.setBorder(new EmptyBorder(1,CMSAdminUtil.COMPONENT_SPACE, 1, 2));
                    JTextField temp = new JTextField();
                    mLabel.setFont(temp.getFont());
                }
                component = mLabel;
                ((JLabel)component).setText((String)x);
            } else if (type.equals(Constants.CHECKBOXTYPE)) {
                if (mCheckBox == null)
                    mCheckBox = new JCheckBox();
                component = mCheckBox;
                if (x instanceof Boolean) {
                    Boolean bool = (Boolean)x;
                    mCheckBox.setHorizontalAlignment(JCheckBox.CENTER);
                    mCheckBox.setSelected(bool.booleanValue());
                }
            } else if (type.equals(Constants.COMBOTYPE)) {
                String[] items = (String[])v.elementAt(1);

                if (mComboBox == null)
                    mComboBox = new JComboBox(items);
                else {
                    mComboBox.removeAllItems();
                    for (int i=0; i<items.length; i++) {
                        mComboBox.insertItemAt(items[i], i);
                    }
                }
                component = mComboBox;
                String str = (String)x;

                if (str.equals(""))
                    mComboBox.setSelectedIndex(0);
                else
                    mComboBox.setSelectedItem(str);
            }
        }

    }
}


