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
package com.netscape.management.client.components;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JViewport;
import javax.swing.ListSelectionModel;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

/**
  * DetailTable is a table component that offers the following
  * functionality above and beyond JTable:
  *
  * - detail area that shows information about the selected row in the table
  * - column customization dialog
  * - smart column sizing based on width of data
  * - sorting support, see ISortableTableModel
  * - automatic client-side sorting
  * - UI configuration state stored in Preferences
  * - various JFC bug fixes
  * - standard behavior and visuals that match and promote
  *    Console Look and Feel guidelines
  *
  * @author Andy Hakim
  */
public class DetailTable extends JComponent
{
    Table table = null;
    JPanel panel = null;
    JComponent panelAggregate = null;
    JComponent tableAggregate = null;
    JSplitPane splitpane = null;
    TableModel tableModel = null;
    JTextArea panelLabels[] = null;
    int lastSelectedRow = -1;
    boolean isInitialized = false;

    protected boolean showTableScollBars = true;
    protected boolean showPanelScollBars = true;

    /**
     * Constructs a DetailTable which is initialized with a default
     * data model, a default column model, and a default selection
     * model.
     *
     * @see JTable#createDefaultDataModel
     * @see JTable#createDefaultColumnModel
     * @see JTable#createDefaultSelectionModel
     */
    public DetailTable()
    {
        this(null, null, null);
    }

    /**
     * Constructs a DetailTable which is initialized with <i>dm</i> as the
     * data model, a default column model, and a default selection
     * model.
     *
     * @param dm        The data model for the table
     * @see JTable#createDefaultColumnModel
     * @see JTable#createDefaultSelectionModel
     */
    public DetailTable(TableModel dm)
    {
        this(dm, null, null);
    }

    /**
     * Constructs a DetailTable which is initialized with <i>dm</i> as the
     * data model, a default column model, and a default selection
     * model.  Optional control over client side sorting.
     *
     * @param dm        The data model for the table
     * @see JTable#createDefaultColumnModel
     * @see JTable#createDefaultSelectionModel
     */
    public DetailTable(TableModel dm, boolean enableClientSideSorting)
    {
        this((enableClientSideSorting ? new TableSorter(dm) : dm), null, null);
    }

    /**
     * Constructs a DetailTable which is initialized with <i>dm</i> as the
     * data model, <i>cm</i> as the column model, and a default selection
     * model.
     *
     * @param dm        The data model for the table
     * @param cm        The column model for the table
     * @see JTable#createDefaultSelectionModel
     */
    public DetailTable(TableModel dm, TableColumnModel cm)
    {
        this(dm, cm, null);
    }

    /**
     * Constructs a DetailTable which is initialized with <i>dm</i> as the
     * data model, <i>cm</i> as the column model, and <i>sm</i> as the
     * selection model.  If any of the parameters are <b>null</b> this
     * method will initialize the table with the corresponding
     * default model. The <i>autoCreateColumnsFromModel</i> flag is set
     * to false if <i>cm</i> is non-null, otherwise it is set to true
     * and the column model is populated with suitable TableColumns
     * for the columns in <i>dm</i>.
     *
     * @param dm        The data model for the table
     * @param cm        The column model for the table
     * @param sm        The row selection model for the table
     * @see JTable#createDefaultDataModel
     * @see JTable#createDefaultColumnModel
     * @see JTable#createDefaultSelectionModel
     */
    public DetailTable(TableModel dm, TableColumnModel cm, ListSelectionModel sm)
    {
        table = new Table(dm, cm, sm);
        tableModel = dm;
    }

    /**
     * Constructs a DetailTable with <i>numRows</i> and <i>numColumns</i> of
     * empty cells using the DefaultTableModel.  The columns will have
     * names of the form "A", "B", "C", etc.
     *
     * @param numRows           The number of rows the table holds
     * @param numColumns        The number of columns the table holds
     * @see javax.swing.table.DefaultTableModel
     */
    public DetailTable(int numRows, int numColumns) {
        this(new DefaultTableModel(numRows, numColumns));
    }

    /**
     * Constructs a DetailTable to display the values in the Vector of Vectors,
     * <i>rowData</i>, with column names, <i>columnNames</i>.
     * The Vectors contained in <i>rowData</i> should contain the values
     * for that row. In other words, the value of the cell at row 1,
     * column 5 can be obtained with the following code:
     * <p>
     * <pre>((Vector)rowData.elementAt(1)).elementAt(5);</pre>
     * <p>
     * All rows must be of the same length as <i>columnNames</i>.
     * <p>
     * @param rowData           The data for the new table
     * @param columnNames       Names of each column
     */
    public DetailTable(final Vector rowData, final Vector columnNames) {
        this(new AbstractTableModel() {
            public String getColumnName(int column) { return columnNames.elementAt(column).toString(); }
            public int getRowCount() { return rowData.size(); }
            public int getColumnCount() { return columnNames.size(); }
            public Object getValueAt(int row, int column) {
                return ((Vector)rowData.elementAt(row)).elementAt(column);
            }
            public boolean isCellEditable(int row, int column) { return true; }
            public void setValueAt(Object value, int row, int column) {
                ((Vector)rowData.elementAt(row)).setElementAt(value, column);
                fireTableCellUpdated(row, column);
            }
        });
    }

    /**
     * Returns Table component used by this DetailTable
     * TODO: improve Javadocs
     */
    public Table getTable()
    {
        return table;
    }

    public void addNotify()
    {
        super.addNotify();
        if(!isInitialized)
            initialize();
    }

    protected void initialize()
    {
        isInitialized = true;
        JComponent c = null;
        setLayout(new BorderLayout());

        tableAggregate = table;
        if(showTableScollBars)
        {
            tableAggregate = JTable.createScrollPaneForTable(table);
        }

        panelAggregate = panel = new DetailPanel();

        GridBagLayout gbl = new GridBagLayout();
        panel.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(0,0,0,5);
        int numColumns = tableModel.getColumnCount();
        panelLabels = new JTextArea[numColumns];

        for(int colIndex = 0; colIndex < numColumns; colIndex++)
        {
            PanelHeader panelHeader = new PanelHeader(table.getColumnName(colIndex));
            gbc.gridx = 0;
            gbc.weightx = 0.0;
            gbc.fill = GridBagConstraints.BOTH;
            gbl.setConstraints(panelHeader, gbc);
            panel.add(panelHeader);

            JTextArea label = new JTextArea();
            label.setFont(table.getFont());
            label.setEditable(false);
            label.setLineWrap(true);
            // label.setWrapStyleWord(true);  // JDK1.2.2: this causes visual problems
            label.setOpaque(false);
            label.setText(" ");
            panelLabels[colIndex] = label;
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            gbc.fill = GridBagConstraints.BOTH;
            gbl.setConstraints(label, gbc);
            panel.add(label);

            gbc.gridy = GridBagConstraints.RELATIVE;
        }

        JPanel spacerPanel = new JPanel();
        spacerPanel.setPreferredSize(new Dimension(0,0));
        gbc.gridx = 0;
        gbc.gridy = GridBagConstraints.RELATIVE;
        gbc.gridwidth = 2;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0,0,0,0);
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbl.setConstraints(spacerPanel, gbc);
        panel.add(spacerPanel);

        if(showPanelScollBars)
        {
            JScrollPane sp = new JScrollPane(panel);
            sp.setBorder(BorderFactory.createEmptyBorder());
            panelAggregate = sp;
        }

        splitpane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitpane.setTopComponent(tableAggregate);
        splitpane.setBottomComponent(panelAggregate);
        splitpane.setOneTouchExpandable(true);
        splitpane.setDividerSize(8); // needed for Windows LF
        c = splitpane;
        tableAggregate.setMinimumSize(new Dimension(0, Integer.MAX_VALUE));

        this.addComponentListener(new ComponentAdapter()
            {
                public void componentResized(ComponentEvent e)
                {
                    sizeDetailPanel();
                }
            });

        ListSelectionModel lsm = table.getSelectionModel();
        lsm.addListSelectionListener(new ListSelectionListener()
            {
                public void valueChanged(ListSelectionEvent e)
                {
                    int selectedRow = table.getSelectedRow();
                    if(selectedRow != lastSelectedRow)
                    {
                        rowSelected(table, panel, selectedRow);
                        lastSelectedRow = selectedRow;
                    }
                }
            });

        tableModel.addTableModelListener(new TableModelListener()
            {
                public void tableChanged(TableModelEvent e)
                {
                    int selectedRow = table.getSelectedRow();
                    if(selectedRow != lastSelectedRow)
                    {
                        rowSelected(table, panel, selectedRow);
                        lastSelectedRow = selectedRow;
                    }
                }
            });

        add(c);
    }

    protected void sizeDetailPanel()
    {
        int newLocation = (int)getSize().getHeight();
        if(newLocation != 0)
        {
            newLocation -= panelAggregate.getPreferredSize().getHeight();
            newLocation -= splitpane.getInsets().bottom;
            newLocation -= splitpane.getDividerSize();
            newLocation -= 1; // needed fudge factor
            splitpane.setDividerLocation(newLocation);

            JTableHeader header = table.getTableHeader();
            header.validate();
            header.repaint();
            table.validate();
            table.repaint();
        }
    }


    /**
     * TODO: improve Javadocs
     */
    protected void rowSelected(JTable t, JPanel p, int rowIndex)
    {
        String labelText = null;
        int numColumns = t.getColumnCount();
        TableModel tableModel = t.getModel();
        for(int colIndex = 0; colIndex < numColumns; colIndex++)
        {
            if(rowIndex != -1)
            {
                Object value = tableModel.getValueAt(rowIndex, colIndex);
                labelText = value.toString();
            }
            else
                labelText = " ";
            JTextArea label = panelLabels[colIndex];
            label.setText(labelText);
        }
    }
}


/**
 * TODO: improve Javadocs
 */
class DetailPanel extends JPanel implements Scrollable
{
    /**
     * Returns the preferred size of the viewport for a view component.
     * For example the preferredSize of a JList component is the size
     * required to acommodate all of the cells in its list however the
     * value of preferredScrollableViewportSize is the size required for
     * JList.getVisibleRowCount() rows.   A component without any properties
     * that would effect the viewport size should just return
     * getPreferredSize() here.
     *
     * @return The preferredSize of a JViewport whose view is this Scrollable.
     * @see JViewport#getPreferredSize
     */
    public Dimension getPreferredScrollableViewportSize()
    {
        return getPreferredSize();
    }


    /**
     * Components that display logical rows or columns should compute
     * the scroll increment that will completely expose one new row
     * or column, depending on the value of orientation.  Ideally,
     * components should handle a partially exposed row or column by
     * returning the distance required to completely expose the item.
     * <p>
     * Scrolling containers, like JScrollPane, will use this method
     * each time the user requests a unit scroll.
     *
     * @param visibleRect The view area visible within the viewport
     * @param orientation Either SwingConstants.VERTICAL or SwingConstants.HORIZONTAL.
     * @param direction Less than zero to scroll up/left, greater than zero for down/right.
     * @return The "unit" increment for scrolling in the specified direction
     * @see JScrollBar#setUnitIncrement
     */
    public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction)
    {
        if(orientation == SwingConstants.VERTICAL)
        {
            Component c = getComponent(0);
            return (int)c.getSize().getHeight();
        }
        return 10;
    }


    /**
     * Components that display logical rows or columns should compute
     * the scroll increment that will completely expose one block
     * of rows or columns, depending on the value of orientation.
     * <p>
     * Scrolling containers, like JScrollPane, will use this method
     * each time the user requests a block scroll.
     *
     * @param visibleRect The view area visible within the viewport
     * @param orientation Either SwingConstants.VERTICAL or SwingConstants.HORIZONTAL.
     * @param direction Less than zero to scroll up/left, greater than zero for down/right.
     * @return The "block" increment for scrolling in the specified direction.
     * @see JScrollBar#setBlockIncrement
     */
    public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction)
    {
        return getScrollableUnitIncrement(visibleRect, orientation, direction);
    }


    /**
     * Return true if a viewport should always force the width of this
     * Scrollable to match the width of the viewport.  For example a noraml
     * text view that supported line wrapping would return true here, since it
     * would be undesirable for wrapped lines to disappear beyond the right
     * edge of the viewport.  Note that returning true for a Scrollable
     * whose ancestor is a JScrollPane effectively disables horizontal
     * scrolling.
     * <p>
     * Scrolling containers, like JViewport, will use this method each
     * time they are validated.
     *
     * @return True if a viewport should force the Scrollables width to match its own.
     */
    public boolean getScrollableTracksViewportWidth()
    {
        return true;
    }

    /**
     * Return true if a viewport should always force the height of this
     * Scrollable to match the height of the viewport.  For example a
     * columnar text view that flowed text in left to right columns
     * could effectively disable vertical scrolling by returning
     * true here.
     * <p>
     * Scrolling containers, like JViewport, will use this method each
     * time they are validated.
     *
     * @return True if a viewport should force the Scrollables height to match its own.
     */
    public boolean getScrollableTracksViewportHeight()
    {
        return false;
    }
}


/**
 * TODO: improve Javadocs
 */
class PanelHeader extends JButton
{
    public PanelHeader(String text)
    {
        setText(text);
        setHorizontalAlignment(SwingConstants.RIGHT);
        setHorizontalTextPosition(SwingConstants.RIGHT);
        setBorder(new FlatBorder());
        setFocusPainted(false);
    }

    public boolean isFocusTraversable()
    {
        return false;
    }
}
