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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.io.Serializable;
import java.util.EventObject;
import java.util.Vector;

import javax.swing.JComponent;
import javax.swing.JPasswordField;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.event.EventListenerList;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableModel;

import com.netscape.certsrv.common.Constants;

/**
 * Class that will edit components correctly in table
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class GenericCellEditor implements TableCellEditor, Serializable {

    protected EventListenerList listenerList = new EventListenerList();
    transient protected ChangeEvent changeEvent = null;
    protected JComponent editorComponent;
    protected JTextField mTextField = new JTextField();
    protected JPasswordField mPasswordField = new JPasswordField();

    protected EditorDelegate delegate = new EditorDelegate();
    protected int clickCounts = 2;

    public GenericCellEditor() {
        mTextField.addActionListener(delegate);
        mPasswordField.addActionListener(delegate);
    }

    @Override
    public Component getTableCellEditorComponent(JTable table, Object value,
        boolean isSelected, int row, int column) {

        TableModel model = table.getModel();

        Vector<Object> v = (Vector<Object>)(((CMSContentTableModel)model).getObjectValueAt(row));
        delegate.setValue(value, v);

        return editorComponent;
    }

    public Component getComponent() {
        return editorComponent;
    }

    @Override
    public Object getCellEditorValue() {
         return delegate.getCellEditorValue();
    }

    @Override
    public boolean isCellEditable(EventObject anEvent) {
        if (anEvent instanceof MouseEvent) {
            if (((MouseEvent)anEvent).getClickCount() < clickCounts)
                return false;
        }
        return delegate.isCellEditable(anEvent);
    }

    @Override
    public boolean shouldSelectCell(EventObject anEvent) {
        boolean retValue = true;

        if (this.isCellEditable(anEvent)) {
            if (anEvent == null || ((MouseEvent)anEvent).getClickCount() >=
                clickCounts)
               retValue = delegate.startCellEditing(anEvent);
        }
        // By default we want the cell the be selected so
        // we return true
        return retValue;
    }

    @Override
    public boolean stopCellEditing() {
        boolean stopped = delegate.stopCellEditing();

        if (stopped) {
            fireEditingStopped();
        }

        return stopped;
    }

    @Override
    public void cancelCellEditing() {
        delegate.cancelCellEditing();
        fireEditingCanceled();
    }

    @Override
    public void addCellEditorListener(CellEditorListener l) {
        listenerList.add(CellEditorListener.class, l);
    }

    @Override
    public void removeCellEditorListener(CellEditorListener l) {
        listenerList.remove(CellEditorListener.class, l);
    }

    /*
     * Notify all listeners that have registered interest for
     * notification on this event type.  The event instance
     * is lazily created using the parameters passed into
     * the fire method.
     * @see EventListenerList
     */
    protected void fireEditingStopped() {
        // Guaranteed to return a non-null array
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

    /*
     * Notify all listeners that have registered interest for
     * notification on this event type.  The event instance
     * is lazily created using the parameters passed into
     * the fire method.
     * @see EventListenerList
     */
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

    protected class EditorDelegate implements ActionListener, ItemListener,
      Serializable {
        protected Object value;

        public Object getCellEditorValue() {
            if (editorComponent instanceof JPasswordField)
                return mPasswordField.getText();
            else if (editorComponent instanceof JTextField)
                return mTextField.getText();

            return null;
        }

        public void setValue(Object x, Vector<Object> v) {
            String type = (String)v.elementAt(0);
            this.value = x;

            if (type.equals(Constants.TEXTTYPE)) {
                if (mTextField == null)
                    mTextField = new JTextField();
                editorComponent = mTextField;
                if (x != null)
                    mTextField.setText(x.toString());
                else
                    mTextField.setText("");
            } else if (type.equals(Constants.PASSWORDTYPE)) {
                if (mPasswordField == null)
                    mPasswordField = new JPasswordField();
                editorComponent = mPasswordField;
                if (x != null)
                    mPasswordField.setText(x.toString());
                else
                    mPasswordField.setText("");
                //((JPasswordField)editorComponent).setCaretPosition(0);
            }
        }

        public boolean isCellEditable(EventObject anEvent) {
            return true;
        }

        public boolean startCellEditing(EventObject anEvent) {
            if (anEvent == null)
                editorComponent.requestFocus();
            return true;
        }

        public boolean stopCellEditing() {
            return true;
        }

        public void cancelCellEditing() {
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            fireEditingStopped();
        }

        @Override
        public void itemStateChanged(ItemEvent e) {
            fireEditingStopped();
        }
    }
}
