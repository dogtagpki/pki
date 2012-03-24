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
package com.netscape.admin.certsrv.config;

import java.awt.Component;
import java.awt.event.*;
import java.awt.AWTEvent;
import java.lang.Boolean;
import javax.swing.table.*;
import javax.swing.event.*;
import java.util.EventObject;
import javax.swing.tree.*;
import java.io.Serializable;
import javax.swing.*;

public class ProfileComponentCellEditor implements TableCellEditor {
    protected EventListenerList listenerList = new EventListenerList();
    protected ChangeEvent changeEvent = null;
                                  
    protected JComponent editorComponent = null;
    protected JComponent container = null;          // Can be tree or table

    public Component getComponent() {
        return editorComponent;
    }
                                  
    public Object getCellEditorValue() {
        return editorComponent;
    }

    public boolean isCellEditable(EventObject anEvent) {
        return true;
    }
                                  
    public boolean shouldSelectCell(EventObject anEvent) {
        return true;
    }
                                  
    public boolean stopCellEditing() {
        fireEditingStopped();
        return true;
    }
                                  
    public void cancelCellEditing() {
        fireEditingCanceled();
    }
                                  
    public void addCellEditorListener(CellEditorListener l) {
        listenerList.add(CellEditorListener.class, l);
    }
                                  
    public void removeCellEditorListener(CellEditorListener l) {
        listenerList.remove(CellEditorListener.class, l);
    }
                                  
    protected void fireEditingStopped() {
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
             if (listeners[i]==CellEditorListener.class) {
                 // Lazily create the event:
                 if (changeEvent == null)
                     changeEvent = new ChangeEvent(this);
                 ((CellEditorListener)listeners[i+1]).editingStopped(changeEvent);
             }              
        }
    }
                                  
    protected void fireEditingCanceled() {
        // Guaranteed to return a non-null array
        Object[] listeners = listenerList.getListenerList();
        // Process the listeners last to first, notifying
        // those that are interested in this event
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==CellEditorListener.class) {
                // Lazily create the event:
                if (changeEvent == null)
                    changeEvent = new ChangeEvent(this);
                ((CellEditorListener)listeners[i+1]).editingCanceled(changeEvent);
            }              
        }
    }
                                  
    // implements javax.swing.table.TableCellEditor
    public Component getTableCellEditorComponent(JTable table, Object value,
        boolean isSelected, int row, int column) {
                                          
        editorComponent = (JComponent)value;
        container = table;
        return editorComponent;
    }
} // End of class JComponentCellEditor

