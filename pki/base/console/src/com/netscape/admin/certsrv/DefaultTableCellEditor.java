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

import com.netscape.certsrv.common.*;
import java.awt.Component;
import java.awt.event.*;
import java.awt.AWTEvent;
import java.lang.Boolean;
import javax.swing.table.*;
import javax.swing.event.*;
import java.util.EventObject;
import javax.swing.*;
import javax.swing.tree.*;
import com.netscape.management.client.util.*;

/**
 * Default Table Cell Editor. Since we need to display different
 * editor depending on serverside input. We will use this editor
 * that takes specific data object.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class DefaultTableCellEditor
    implements TableCellEditor, ActionListener
{

    /*==========================================================
     * variables
     *==========================================================*/

    /** Event listeners */
    protected EventListenerList listenerList = new EventListenerList();
    transient protected ChangeEvent changeEvent = null;
    protected CellEditorData mValue;

    protected JTextField mTextField = new JTextField();
    protected JPasswordField mPasswordField = new JPasswordField();
    protected JTextField mEditorComponent;
    protected int clickCountToStart = 2;

    /*==========================================================
     * constructors
     *==========================================================*/
    public DefaultTableCellEditor() {
        mTextField = new JTextField();
        mTextField.addActionListener(this);
        mPasswordField = new JPasswordField();
        mPasswordField.addActionListener(this);
        mValue = new CellEditorData();
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    public Component getComponent() {
        return mEditorComponent;
    }

    /**
     *  clickCountToStart controls the number of clicks required to start
     *  editing if the event passed to isCellEditable() or startCellEditing() is
     *  a MouseEvent.  For example, by default the clickCountToStart for
     *  a JTextField is set to 2, so in a JTable the user will need to
     *  double click to begin editing a cell.
     */
    public void setClickCountToStart(int count) {
        clickCountToStart = count;
    }

    /**
     *  clickCountToStart controls the number of clicks required to start
     *  editing if the event passed to isCellEditable() or startCellEditing() is
     *  a MouseEvent.  For example, by default the clickCountToStart for
     *  a JTextField is set to 2, so in a JTable the user will need to
     *  double click to begin editing a cell.
     */
    public int getClickCountToStart() {
        return clickCountToStart;
    }

    //Interface javax.swing.CellEditor
    public Object getCellEditorValue() {
        mValue.mData = mEditorComponent.getText();
        return mValue;
    }

    public boolean isCellEditable(EventObject anEvent) {
        if (anEvent instanceof MouseEvent) {
            if (((MouseEvent)anEvent).getClickCount() < clickCountToStart)
            return false;
        }
        return true;
    }

    public boolean shouldSelectCell(EventObject anEvent) {
        boolean retValue = true;

        if (this.isCellEditable(anEvent)) {
            if (anEvent == null || ((MouseEvent)anEvent).getClickCount() >=
                clickCountToStart)
            retValue = startCellEditing(anEvent);
        }

        // By default we want the cell the be selected so
        // we return true
        return retValue;

    }

    public boolean startCellEditing(EventObject anEvent) {
        if(anEvent == null)
            mEditorComponent.requestFocus();
        return true;
    }

    public boolean stopCellEditing() {
        fireEditingStopped();
        return true;
    }

    public void cancelCellEditing() {
        fireEditingCanceled();
    }

    //  Handle the event listener bookkeeping
    public void addCellEditorListener(CellEditorListener l) {
        listenerList.add(CellEditorListener.class, l);
    }

    public void removeCellEditorListener(CellEditorListener l) {
        listenerList.remove(CellEditorListener.class, l);
    }

    // Implementing ActionListener interface
        public void actionPerformed(ActionEvent e) {
        fireEditingStopped();
    }

    public Component getTableCellEditorComponent(JTable table,
                         Object value,
                         boolean isSelected,
                         int row, int column) {

        Debug.println("DefaultTableCellEditor: getTableCellEditorComponent() -");
        if(value != null) {
            Debug.println("  data: "+(String)((CellEditorData)value).mData);
            Debug.println("  type: "+((CellEditorData)value).mType);
        }
        Debug.println("  isSelected: "+isSelected);
        Debug.println("  row:"+row +" col:"+column);

        mEditorComponent = mTextField;
        if(value != null) {
            mValue = (CellEditorData)value;

            if (mValue.mType.equals(Constants.TYPE_PASSWORD))
                mEditorComponent = mPasswordField;
            mEditorComponent.setText((String)mValue.mData);
        } else {
            mEditorComponent.setText("");
        }
        return mEditorComponent;
    }

    /*==========================================================
     * protected methods
     *==========================================================*/

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

    /*==========================================================
     * private methods
     *==========================================================*/


}
