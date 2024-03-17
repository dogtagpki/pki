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
package com.netscape.management.nmclf;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.*;
import java.util.EventObject;

/**
 * An checkbox editor for use in JTable to edit
 *   Boolean values.  We define this rather than
 *   using the "default" Boolean editor provided
 *   by JTable so we can get a more natural feel
 *   to changing the checkboxes.  With the default
 *   editor, a checkbox must be "activated" before
 *   its state can be changed
 * 
 * @author  terencek
 * @see     com.netscape.management.nmclf.SuiCheckCellRenderer
 */
public class SuiCheckCellEditor extends SuiCheckCellRenderer 
implements TableCellEditor {
    private ChangeEvent changeEvent = new ChangeEvent(this);
    private int currentRow, currentColumn;
    private JTable currentTable;
    
    /**
     * constructor
     */
    public SuiCheckCellEditor() {
        getCheckBox().addItemListener(
                                      new ItemListener() {
                                      public void itemStateChanged(ItemEvent e) {
                                      currentTable.getModel().setValueAt(
                                                                         getCheckBox().isSelected()?
                                                                         Boolean.TRUE:Boolean.FALSE, currentRow,
                                                                         currentColumn);
                                  }
                                  }
                                      );
    }
    
    /**
     * do nothing if add cell editor listener
     *
     * @param newListener new listener to be added to the listener queue
     */
    public void addCellEditorListener(
                                      CellEditorListener newListener) {
        // do nothing -- we're handling changes directly
    }
    
    /**
     * do nothing if cancel cell editing
     */
    public void cancelCellEditing() {
    }
    
    /**
     * Get the current state of the checkbox
     *
     * @return the boolean value of the checkbox
     */
    public Object getCellEditorValue() {
        return getCheckBox().isSelected() ? 
                  Boolean.TRUE : 
        Boolean.FALSE;
    }
    
    /**
     * Return a checkbox to edit the data value
     *
     * @param table JTable which contains this checkbox
     * @param value the value of the object
     * @param isSelected selection state
     * @param row row of the checkbox
     * @param column column of the checkbox
     * @return the checkbox component
     */
    public Component getTableCellEditorComponent(
                                                 JTable table, 
                                                 Object value, 
                                                 boolean isSelected, 
                                                 int row, 
                                                 int column) {
        if (value == null) 
            value = Boolean.FALSE;
        
        // toggle the state of the data so activating
        //  the editor looks like a toggle
        Boolean antiValue = ((Boolean)value).booleanValue() ? 
                  Boolean.FALSE:Boolean.TRUE;
        
        ((AbstractTableModel)table.getModel()).setValueAt(antiValue,row,column);
        
        currentTable  = table;
        currentRow    = row;
        currentColumn = column;
        
        return getTableCellRendererComponent(table,antiValue,isSelected,
                                             true,row,column);
    }
    
    /**
     * Allow all cells to be edited
     *
     * @param anEvent event
     * @return always allow the cell to be edited.
     */
    public boolean isCellEditable(EventObject anEvent) {
        return true;
    }
    
    /**
     * remove the cell editor listener
     *
     * @param newListener listener to be added
     */
    public void removeCellEditorListener(CellEditorListener newListener) {
        // do nothing
    }
    
    /**
     * Always select the cell being edited
     *
     * @param anEvent event
     * @return boolean which indicated whether the cell should selected or not
     */
    public boolean shouldSelectCell(EventObject anEvent) {
        return true;
    }
    
    /**
     * Always allow the edit to stop
     *
     * @return always allow the cell to stop editing
     */
    public boolean stopCellEditing() {
        return true;
    }
}
