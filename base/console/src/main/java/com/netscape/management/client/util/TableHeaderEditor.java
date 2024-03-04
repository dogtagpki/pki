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
package com.netscape.management.client.util;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.text.*;
import com.netscape.management.nmclf.SuiLookAndFeel;
import com.netscape.management.nmclf.SuiTable;


/**
 * TableHeaderEditor allows users to customize the table columns to display
 * different values. A user is provided with a list of possible items, the
 * current list of items being viewed, and the actual table column names for
 * the current list of items being viewed.
 *
 * @author  Peter Lee (phlee@netscape.com)
 */
public class TableHeaderEditor extends AbstractModalDialog {

    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.util.default");
    private static final String EMPTY_STRING = new String("");

    private JList _list;
    private DefaultListModel _listModel;
    private JTable _table;
    private TableHeaderEditorModel _tableModel;
    private ListSelectionModel _tableSelectionModel;
    private JLabel _listLabel;
    private JButton _addButton;
    private JButton _removeButton;
    private JButton _moveUpButton;
    private JButton _moveDownButton;
    private JLabel _selectedLabel;
    private JLabel _selected;
    private JLabel _selectedNameLabel;
    private JTextField _selectedName;
    private String _revertSelectedName;
    private Help _helpSession;


    /**
     * Constructor for the dialog
    *
    * @param frame  dialog's parent frame
    * @param title  dialog title
    * @param listLabel  label for the list
    * @param selectedLabel  label for the selected value to display
    * @param selectedNameLabel  label for the name to display the selected value as
    * @param availableValues  values for the list
    * @param currentValues  selected values
    * @param currentDisplayNames  names for the selected values
     */
    public TableHeaderEditor(Frame frame, String title,
            String listLabel, String selectedLabel,
            String selectedNameLabel, String[] availableValues,
            Vector currentValues, Vector currentDisplayNames) {
        // This is a modal dialog to support synchronous processing, i.e.,
        // usage involves displaying the dialog, user interacting with the
        // dialog, and the code retrieving the data from the dialog before
        // continuing.
        super(frame, title);

        _helpSession = new Help(_resource);

        _listLabel = new JLabel(listLabel);

        _listModel = new DefaultListModel();
        _list = new JList(_listModel);
        _list.addListSelectionListener(new DialogListSelectionListener());
        _list.setSelectionMode(
                ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        JScrollPane listScroller = new JScrollPane();
        listScroller.getViewport().setView(_list);
        listScroller.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));

        DialogButtonPanel buttonPanel =
                new DialogButtonPanel(new DialogActionListener());

        String[] columns = new String[]{ selectedLabel, selectedNameLabel };
        _tableModel = new TableHeaderEditorModel(columns);
        _table = new SuiTable(_tableModel);
        _tableSelectionModel = _table.getSelectionModel();
        _tableSelectionModel.addListSelectionListener(
                new DialogTableSelectionListener());
        _table.setColumnSelectionAllowed(false);
        _table.setCellSelectionEnabled(false);
        _table.setRowSelectionAllowed(true);
        _table.setShowGrid(false);
        _table.getTableHeader().setReorderingAllowed(false);
        JScrollPane tableScroller =
                SuiTable.createScrollPaneForTable(_table);
        tableScroller.getViewport().setBackground(Color.white);

        _selectedLabel = new JLabel(selectedLabel);
        _selected = new JLabel();
        _selected.setBorder(new BevelBorder(BevelBorder.LOWERED));
        _selectedNameLabel = new JLabel(selectedNameLabel);
        _selectedName = new JTextField();
        Document selectedNameDoc = _selectedName.getDocument();
        selectedNameDoc.addDocumentListener(new DialogDocumentListener());
        _revertSelectedName = EMPTY_STRING;

        //setValues(availableValues, currentValues, currentDisplayNames);
        setValuesSorted(availableValues, currentValues,
                currentDisplayNames);

        // Component layout
        JPanel leftPanel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(leftPanel, _listLabel, 0, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                0, 0, 0, 0);
        GridBagUtil.constrain(leftPanel, listScroller, 0, 1,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        JPanel subPanel1 = new JPanel( new GridLayout(1, 2,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0));
        subPanel1.add(_selectedLabel);
        subPanel1.add(_selectedNameLabel);

        JPanel subPanel2 = new JPanel( new GridLayout(1, 2,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0));
        subPanel2.add(_selected);
        subPanel2.add(_selectedName);

        JPanel selectionPanel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(selectionPanel, subPanel1, 0, 0,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.RELATIVE, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        GridBagUtil.constrain(selectionPanel, subPanel2, 0, 1,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        JPanel rightPanel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(rightPanel, selectionPanel, 0, 0,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.RELATIVE, 1.0, 0.0,
                GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0);
        GridBagUtil.constrain(rightPanel, tableScroller, 0, 1,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(panel, leftPanel, 0, 0, 1,
                GridBagConstraints.REMAINDER, 0.5, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                0, 0, SuiLookAndFeel.SEPARATED_COMPONENT_SPACE);
        GridBagUtil.constrain(panel, buttonPanel, 1, 0,
                GridBagConstraints.RELATIVE,
                GridBagConstraints.REMAINDER, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.NONE, 0,
                0, 0, SuiLookAndFeel.SEPARATED_COMPONENT_SPACE);
        GridBagUtil.constrain(panel, rightPanel, 2, 0,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 0.5, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        setPanel(panel);

        // Set widths
        int width = 140;
        int height = 200;

        listScroller.setMinimumSize(new Dimension(width * 3 / 2, height));
        tableScroller.setMinimumSize(new Dimension(width * 2, height));

        String identifier = _tableModel.getColumnName(0);
        if (identifier != null) {
            TableColumn column = _table.getColumn(identifier);
            column.setWidth(width);
        }

        setSize(640, 400);
    }


    /**
      * The deprecation warning for this is erroneous. This method
      * overrides Dialog.show(). It is safe to ignore warning.
      */
    public void show() {
        ModalDialogUtil.setDialogLocation(this, null);
        super.show();
    }


    /**
      * Returns a vector for the table column values.
     * @return vector for the table column values
      */
    public Vector getColumnValues() {
        int count = _tableModel.getRowCount();
        if (count > 0) {
            Vector values = new Vector();
            for (int i = 0; i < count; i++) {
                values.addElement(_tableModel.getValueAt(i, 0));
            }
            return values;
        }
        return null;
    }


    /**
      * Returns a vector for the table column names for the table column values.
     * @return vector for the table column names
      */
    public Vector getColumnNames() {
        int count = _tableModel.getRowCount();
        if (count > 0) {
            Vector values = new Vector();
            for (int i = 0; i < count; i++) {
                values.addElement(_tableModel.getValueAt(i, 1));
            }
            return values;
        }
        return null;
    }


    /**
      * Implements the method to handle help event.
      */
    public void helpInvoked() {
        _helpSession.contextHelp("TableHeaderEditor");
    }


    /**
      * Handles add event to move value from available list to selected table.
      */
    public void addInvoked() {
        Object[] rowsToAdd = _list.getSelectedValues();
        int[] rowsToRemove = _list.getSelectedIndices();
        for (int i = rowsToRemove.length - 1; i >= 0; i--) {
            _listModel.removeElementAt(rowsToRemove[i]);
        }
        _tableModel.addTableValues(rowsToAdd);
        if (_tableModel.getRowCount() > 0) {
            setOKButtonEnabled(true);
        }
        _list.clearSelection(); // Clear any residual selection
    }


    /**
      * Handles remove event to move value from selected table to available list.
      */
    public void removeInvoked() {
        int[] rowsToRemove = _table.getSelectedRows();
        String[] objects = new String[rowsToRemove.length];
        for (int i = rowsToRemove.length - 1; i >= 0; i--) {
            // Remove from table.
            objects[i] = (String)_tableModel.getValueAt(rowsToRemove[i], 0);
            _tableModel.removeRow(rowsToRemove[i]);
        }

        sort(objects, 0, objects.length - 1); // Need sorted items to do list selection.

        for (int i = 0; i < rowsToRemove.length; i++) {
            // Add to list using insertion sort.
            int listCount = _listModel.getSize();
            int j = 0;
            for (; j < listCount; j++) {
                if (isGreater((String)_listModel.getElementAt(j),
                        objects[i])) {
                    _listModel.add(j, objects[i]);
                    _list.addSelectionInterval(j, j);
                    break;
                }
            }
            if (j == listCount) {
                _listModel.addElement(objects[i]);
                _list.addSelectionInterval(j, j);
            }
        }

        // There has to be at least one entry.
        if (_tableModel.getRowCount() == 0) {
            setOKButtonEnabled(false);
        }

        _table.clearSelection(); // Clear any residual selection
    }


    /**
      * Handles move up event to reorder column values.
      */
    public void moveUpInvoked() {
        int row = _table.getSelectedRow();
        Vector tmVectors = _tableModel.getDataVector();
        // Get handle to row to move. Doing this because moveRow()
        // fails with ArrayIndexOutOfBoundsException.
        Vector rowVector = (Vector) tmVectors.elementAt(row);
        _tableModel.removeRow(row);
        _tableModel.insertRow(row - 1, rowVector);
        _table.setRowSelectionInterval(row - 1, row - 1);
    }


    /**
      * Handles move down event to reorder column values.
      */
    public void moveDownInvoked() {
        int row = _table.getSelectedRow();
        Vector tmVectors = _tableModel.getDataVector();
        // Get handle to row to move. Doing this because moveRow()
        // fails with ArrayIndexOutOfBoundsException.
        Vector rowVector = (Vector) tmVectors.elementAt(row);
        _tableModel.removeRow(row);
        _tableModel.insertRow(row + 1, rowVector);
        _table.setRowSelectionInterval(row + 1, row + 1);
    }


    /**
      * Populates the list and table. Only put items in list that are not in table.
      */
    private void setValues(String[] availableValues,
            Vector currentValues, Vector currentDisplayNames) {
        _tableModel.setTableValues(currentValues, currentDisplayNames);
        for (int i = 0; i < availableValues.length; i++) {
            if (currentValues.indexOf(availableValues[i]) == -1) {
                _listModel.addElement(availableValues[i]);
            }
        }
    }


    /**
      * Populates the list and table. Only put items in list that are not in table.
      */
    private void setValuesSorted(String[] availableValues,
            Vector currentValues, Vector currentDisplayNames) {
        _tableModel.setTableValues(currentValues, currentDisplayNames);
        sort(availableValues, 0, availableValues.length - 1);
        for (int i = 0; i < availableValues.length; i++) {
            if (currentValues.indexOf(availableValues[i]) == -1) {
                _listModel.addElement(availableValues[i]);
            }
        }
    }


    /**
      * Sort an array of strings in ascending order
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
      */
    private boolean isGreater(String a, String b) {
        if (a.compareTo(b) <= 0) {
            return false;
        }
        return true;
    }


    /**
      * Inner class used to handle list selection event.
      */
    class DialogListSelectionListener implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent e) {
            int[] selection = _list.getSelectedIndices();
            if (selection.length == 0) {
                _addButton.setEnabled(false); // Only disable buttons related to list
            } else {
                // Send unselect event to table
                _table.clearSelection();
                _addButton.setEnabled(true);
            }
        }
    }


    /**
      * Inner class used to handle table selection event.
      */
    class DialogTableSelectionListener implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent e) {
            if (_tableSelectionModel.isSelectionEmpty()) {
                _removeButton.setEnabled(false); // Only disable buttons related to table
                _moveUpButton.setEnabled(false);
                _moveDownButton.setEnabled(false);
                _selectedName.setEnabled(false);
                _selected.setText("");
                _selectedName.setText("");
                _revertSelectedName = EMPTY_STRING;
            } else {
                // Send unselect event to list
                _list.clearSelection();
                _removeButton.setEnabled(true); // Enable the remove button for any select count
                if (_table.getSelectedRowCount() > 1) {
                    // Multiple selection
                    _moveUpButton.setEnabled(false);
                    _moveDownButton.setEnabled(false);
                    _selectedName.setEnabled(false);
                    _selected.setText("");
                    _selectedName.setText("");
                    _revertSelectedName = EMPTY_STRING;
                } else {
                    // Single selection
                    if (_table.isRowSelected(0)) {
                        _moveUpButton.setEnabled(false); // Disable move up if first row is selected
                    } else {
                        _moveUpButton.setEnabled(true);
                    }
                    if (_table.isRowSelected(_table.getRowCount() - 1)) {
                        _moveDownButton.setEnabled(false); // Disable move down if last row is selected
                    } else {
                        _moveDownButton.setEnabled(true);
                    }
                    int row = _table.getSelectedRow();
                    _selected.setText(
                            (String)_tableModel.getValueAt(row, 0));
                    _selectedName.setText(
                            (String)_tableModel.getValueAt(row, 1));
                    _selectedName.selectAll(); // Highlight text
                    _selectedName.requestFocus();
                    _revertSelectedName = _selectedName.getText();
                    _selectedName.setEnabled(true);
                }
            }
        }
    }


    /**
      * Inner class used to implement ActionListener.
      */
    class DialogActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("Add")) {
                TableHeaderEditor.this.addInvoked();
            } else if (e.getActionCommand().equals("Remove")) {
                TableHeaderEditor.this.removeInvoked();
            } else if (e.getActionCommand().equals("MoveUp")) {
                TableHeaderEditor.this.moveUpInvoked();
            } else if (e.getActionCommand().equals("MoveDown")) {
                TableHeaderEditor.this.moveDownInvoked();
            }
        }
    }


    /**
      * Inner class used to handle selectedName field change events.
      */
    class DialogDocumentListener implements DocumentListener {
        public void insertUpdate(DocumentEvent e) {
            myUpdate(e);
        }

        public void removeUpdate(DocumentEvent e) {
            myUpdate(e);
        }

        public void changedUpdate(DocumentEvent e) {
            myUpdate(e);
        }

        public void myUpdate(DocumentEvent e) {
            int selectionCount = _table.getSelectedRowCount();
            int row = _table.getSelectedRow();
            if (selectionCount == 1 && row != -1) {
                _tableModel.setValueAt(_selectedName.getText(), row, 1);
            }
        }
    }


    /**
      * Inner class used to layout the dialog buttons in accordance with
      * the L&F spec.
      */
    class DialogButtonPanel extends JPanel {
        DialogButtonPanel(ActionListener listener) {
            String[] labels =
                    new String[]{ _resource.getString("TableHeaderEditor",
                    "addButtonLabel"),
            _resource.getString("TableHeaderEditor", "removeButtonLabel"),
            _resource.getString("TableHeaderEditor", "moveUpButtonLabel"),
            _resource.getString("TableHeaderEditor", "moveDownButtonLabel")};
            JButton[] buttons = JButtonFactory.create(labels);

            _addButton = buttons[0];
            _addButton.setActionCommand("Add");
            _addButton.addActionListener(listener);
            _addButton.setEnabled(false);

            _removeButton = buttons[1];
            _removeButton.setActionCommand("Remove");
            _removeButton.addActionListener(listener);
            _removeButton.setEnabled(false);

            _moveUpButton = buttons[2];
            _moveUpButton.setActionCommand("MoveUp");
            _moveUpButton.addActionListener(listener);
            _moveUpButton.setEnabled(false);

            _moveDownButton = buttons[3];
            _moveDownButton.setActionCommand("MoveDown");
            _moveDownButton.addActionListener(listener);
            _moveDownButton.setEnabled(false);

            setLayout( new GridLayout(4, 1, 0,
                    SuiLookAndFeel.COMPONENT_SPACE));
            add(_addButton);
            add(_removeButton);
            add(_moveUpButton);
            add(_moveDownButton);
        }
    }


    /**
      * Inner class for the table model.
      */
    class TableHeaderEditorModel extends DefaultTableModel {
        TableHeaderEditorModel(String[] columnNames) {
            setColumnIdentifiers(columnNames);
        }

        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false;
        }

        public void setTableValues(Vector values, Vector valueNames) {
            int prevRowCount = getRowCount();
            for (int i = prevRowCount - 1; i >= 0; i--) {
                removeRow(i);
            }

            if (values == null) {
                return;
            }

            int rowCount = values.size();
            int nameCount = -1;
            if (valueNames != null) {
                nameCount = valueNames.size();
            }

            for (int i = 0; i < rowCount; i++) {
                Object[] tableRow = new Object[2];
                tableRow[0] = values.elementAt(i);
                if (i >= 0 && i < nameCount) {
                    tableRow[1] = valueNames.elementAt(i);
                } else {
                    tableRow[1] = null;
                }
                addRow(tableRow);
            }

            fireTableDataChanged();
        }

        public void addTableValues(Object[] values) {
            if (values == null || values.length == 0) {
                return;
            }

            for (int i = 0; i < values.length; i++) {
                Object[] tableRow = new Object[2];
                tableRow[0] = values[i];
                tableRow[1] = new String(values[i].toString());
                addRow(tableRow);
            }

            // Select the added values.
            int endIndex = getRowCount() - 1;
            _table.setRowSelectionInterval(endIndex - values.length +
                    1, endIndex);

            fireTableDataChanged();
        }
    }
}
