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
import javax.swing.table.*;
import javax.swing.border.*;
import javax.swing.*;
import java.io.Serializable;

/**
 * Class that will render label correctly in table
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class LabelCellRenderer
    implements TableCellRenderer, Serializable
{
    /*==========================================================
     * variables
     *==========================================================*/
    protected JComponent component;
    protected ValueProperty value;
    public final static Color HIGHLIGHTCOLOR = new Color(0, 0, 128);
    public final static Color WHITECOLOR = Color.white;
    public final static Color BLACKCOLOR = Color.black;
    
    /*==========================================================
     * constructors
     *==========================================================*/

    public LabelCellRenderer(JLabel x) {
        component = x;
	    x.setOpaque(true);
	    x.setBorder(new EmptyBorder(1,CMSAdminUtil.COMPONENT_SPACE, 1, 2));
	    JTextField temp = new JTextField();
        x.setFont(temp.getFont());
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

        if(value == null) {
            value = table.getModel().getValueAt(row, column);                
        }
        this.value.setValue(value);       
        component.setBackground(isSelected ? HIGHLIGHTCOLOR : WHITECOLOR);
        component.setForeground(isSelected ? WHITECOLOR : BLACKCOLOR);
        return component;
    }


    public class ValueProperty implements Serializable {
        public Object value;

        public void setValue(Object x) {
	        if (x == null) {
	            value = "";
	            //System.out.println("SetValue: x is null");
	        } else {
	            value = x;
	        }
	        if (x instanceof Icon)
	            ((JLabel)component).setIcon((Icon)x);
	        if (x instanceof String)
	            ((JLabel)component).setText(x.toString());
	        if (x instanceof JLabel) {
	            //System.out.println("SetValue: TTIP="+((JLabel)x).getToolTipText());
	            ((JLabel)component).setIcon(((JLabel)x).getIcon());
	            ((JLabel)component).setText(((JLabel)x).getText());
	            ((JLabel)component).setHorizontalAlignment(((JLabel)x).getHorizontalAlignment());
	            ((JLabel)component).setToolTipText(((JLabel)x).getToolTipText());
	        }
        }
        
    }

}


