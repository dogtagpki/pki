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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;

/**
  * Table offers the following above and beyond JTable:
  *
  * - column customization dialog
  * - smart column sizing based on width of data
  * - sorting support, see ISortableTableModel
  * - automatic client-side sorting
  * - UI configuration state stored in Preferences
  * - various JFC bug fixes
  * - standard behavior and visuals that match and promote
  *    Netscape Management Look and Feel guidelines
  *
  * @author Andy Hakim
  */
public class Table extends JTable
{
    public static final int AUTO_RESIZE_DATA = AUTO_RESIZE_ALL_COLUMNS + 1;
	private static final int COLUMN_WIDTH_MULTIPLE = 20;
    private static int ROWS_TO_SCAN = 20;
        
    protected int autoResizeMode = AUTO_RESIZE_OFF;
	private HeaderMouseListener headerMouseListener = new HeaderMouseListener();
    
    boolean isInitialized = false;
    boolean enableClientSideSorting = false;
    
    protected boolean showTableScollBars = true;
    
    /**
     * Constructs a Table which is initialized with a default
     * data model, a default column model, and a default selection
     * model.
     *
     * @see JTable#createDefaultDataModel
     * @see JTable#createDefaultColumnModel
     * @see JTable#createDefaultSelectionModel
     */
    public Table()
    {
        this(null, null, null);
    }

    /**
     * Constructs a Table which is initialized with <i>dm</i> as the
     * data model, a default column model, and a default selection
     * model.
     *
     * @param dm        The data model for the table
     * @see JTable#createDefaultColumnModel
     * @see JTable#createDefaultSelectionModel
     */
    public Table(TableModel dm) 
    {
        this(dm, null, null);
    }

    /**
     * Constructs a Table which is initialized with <i>dm</i> as the
     * data model, a default column model, and a default selection
     * model.  Optional control over client side sorting.
     *
     * @param dm        The data model for the table
     * @see JTable#createDefaultColumnModel
     * @see JTable#createDefaultSelectionModel
     */
    public Table(TableModel dm, boolean enableClientSideSorting)
    {
        this(((enableClientSideSorting && !(dm instanceof ISortableTableModel)) ?
                new TableSorter(dm) : dm), null, null);
        this.enableClientSideSorting = enableClientSideSorting; 
    }
    
    /**
     * Constructs a Table which is initialized with <i>dm</i> as the
     * data model, <i>cm</i> as the column model, and a default selection
     * model.
     *
     * @param dm        The data model for the table
     * @param cm        The column model for the table
     * @see JTable#createDefaultSelectionModel
     */
    public Table(TableModel dm, TableColumnModel cm) 
    {
        this(dm, cm, null);
    }

    /**
     * Constructs a Table which is initialized with <i>dm</i> as the
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
    public Table(TableModel dm, TableColumnModel cm, ListSelectionModel sm) 
    {
        super(dm, cm, sm);
        initialize();
		initializeColumnHeaders();
	}

    /**
     * Constructs a Table with <i>numRows</i> and <i>numColumns</i> of
     * empty cells using the DefaultTableModel.  The columns will have
     * names of the form "A", "B", "C", etc.
     *
     * @param numRows           The number of rows the table holds
     * @param numColumns        The number of columns the table holds
     * @see javax.swing.table.DefaultTableModel
     */
    public Table(int numRows, int numColumns) {
        this(new DefaultTableModel(numRows, numColumns));
    }

    /**
     * Constructs a Table to display the values in the Vector of Vectors,
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
    public Table(final Vector rowData, final Vector columnNames) {
        this(new AbstractTableModel() {
            public String getColumnName(int column) { return columnNames.elementAt(column).toString(); }
            public int getRowCount() { return rowData.size(); }
            public int getColumnCount() { return columnNames.size(); }
            public Object getValueAt(int row, int column) {
                return ((Vector)rowData.elementAt(row)).elementAt(column);
            }
            public boolean isCellEditable(int row, int column) { return false; }
            public void setValueAt(Object value, int row, int column) {
                ((Vector)rowData.elementAt(row)).setElementAt(value, column);
                fireTableCellUpdated(row, column);
            }
        });
        if(!isInitialized)
            initialize();
    }

    /**
     * @overrides JTable@getScrollableTracksViewportWidth
     */
    public boolean getScrollableTracksViewportWidth() 
    {
        Component parent =  getParent();
        if (parent != null && parent instanceof JViewport) {
            return (getPreferredSize().width < parent.getSize().width);
        }
        return false;
    }

    /**
     * @overrides JTable@getScrollableTracksViewportHeigt
     */    
    public boolean getScrollableTracksViewportHeight() 
    {
        Component parent =  getParent();
        if (parent != null && parent instanceof JViewport) {
            return (getPreferredSize().height < parent.getSize().height);
        }
        return false;
    }
    
	private void initializeColumnHeaders()
	{
		TableColumnModel tcm = getColumnModel();
        Enumeration e = tcm.getColumns();
        int viewColumnIndex = 0;
        TableModel tm  = getModel();
        // can't refer to this.enableClientSideSorting here because initializeColumnHeaders
        // can be called from ctor, before this members are set - but the ctor will have
        // wrapped tm in a sortable interface, so check the type of the model to see if it
        // is sortable
        boolean isSortable = (tm instanceof ISortableTableModel);
        while (e.hasMoreElements())
        {
            int columnIndex = convertColumnIndexToModel(viewColumnIndex); 
            int alignment = getTableHeaderAlignmentByClass(tm.getColumnClass(columnIndex));
            TextHeaderRenderer headerRenderer = new TextHeaderRenderer(alignment, isSortable);
            TableColumn column = (TableColumn)e.nextElement();
            column.setHeaderRenderer(headerRenderer);
            viewColumnIndex++;
        }
	}
	
    protected void initialize()
    {
        this.isInitialized = true;
        setIntercellSpacing(new Dimension(0, 0));
        setShowGrid(false);
        setColumnSelectionAllowed(false);
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Miodrag, JDK1.4 port: AUTO_RESIZE_DATA is not working as 
        // ScrollableTracksViewportWidth is set to true. Use JTable
        // built-in column resize modes.
        //setAutoResizeMode(AUTO_RESIZE_DATA);

        setDefaultRenderer(JCheckBox.class, new TableCheckBoxRenderer());
        setDefaultEditor(JCheckBox.class, new TableCheckBoxEditor());
		setDefaultRenderer(JLabel.class, new TableLabelRenderer());
		setDefaultRenderer(Object.class, new TableLabelRenderer());
		
        JTableHeader header = getTableHeader();
        if(header != null)
		{
            header.setUpdateTableInRealTime(false); // improved performance
			header.addMouseListener(headerMouseListener);
		}
		
		// smart column sizing
        addComponentListener(new ComponentAdapter()
            {
               //long lastTimeMillis = 0;
               public void componentResized(ComponentEvent e)
               {
                    if(autoResizeMode == AUTO_RESIZE_DATA)
                    {
                        sizeColumnsByData();
                        /*if(System.currentTimeMillis() - lastTimeMillis > 500)
                        {
                            lastTimeMillis = System.currentTimeMillis();
                            sizeColumnsByData();
                            // System.err.println("resized " + System.currentTimeMillis());
                        }*/
                    }
                    removeComponentListener(this);
               }
            });
		
		// causes all cells to be repainted,
		// needed by custom cell renderers that
		// show select all cells in a row.
		/*
		addFocusListener(new FocusAdapter()
			{
				public void focusGained(FocusEvent e)
				{
					revalidate();
				}
				
				public void focusLost(FocusEvent e)
				{
					revalidate();
				}
			});
		*/
    }

    protected int getTableHeaderAlignmentByClass(Class c)
    {
        if(c.equals(Number.class))
            return JLabel.RIGHT;
        else
        if(c.equals(Date.class))
            return JLabel.RIGHT;
        else
        if(c.equals(ImageIcon.class))
            return JLabel.CENTER;
        else
        if(c.equals(Boolean.class))
            return JLabel.CENTER;
        else
        if(c.equals(Object.class))
            return JLabel.LEFT;
        return this.getTableHeaderAlignmentByClass(c.getSuperclass());
    }

	/**
	 * Sets the data model for this table to newModel and registers 
	 * with it for listener notifications from the new data model.
	 * 
	 * @param dataModel the new data source for this table
	 * @exception IllegalArgumentException if dataModel is null
	 * @see JTable#getModel()
	 */
	public void setModel(TableModel dataModel) throws IllegalArgumentException
	{
	    super.setModel(dataModel);
		initializeColumnHeaders();
	}


	/**
	 * Sets the column model for this table to newModel and registers 
	 * for listener notifications from the new column model. Also sets 
	 * the column model of the JTableHeader to columnModel.
	 * 
	 * @param columnModel the new data source for this table column
	 * @exception IllegalArgumentException if columnModel is null
	 * @see #getColumnModel()
	 */
	public void setColumnModel(TableColumnModel columnModel) throws IllegalArgumentException
	{
		super.setColumnModel(columnModel);
		initializeColumnHeaders();
	}
	
    /**
     * Sets the table's auto resize mode when the table is resized.
     * 
     * AUTO_RESIZE_DATA (default) is a new resizing mode in Table, 
     * which adjusts column widths based on the size of data.
     * 
     * Any other AUTO_RESIZE* value in JTable is also supported.
     * 
     * @param resizeMode any AUTO_RESIZE* constant
     * @overrides JTable#setAutoResizeMode
     */
    public void setAutoResizeMode(int resizeMode)
    {
        autoResizeMode = resizeMode;
        if(resizeMode == AUTO_RESIZE_DATA)
            resizeMode = JTable.AUTO_RESIZE_OFF;
        super.setAutoResizeMode(resizeMode);
    }
    
	/**
	 * Returns the auto resize mode of the table.
	 * @return the autoResizeMode of the table
	 */
    public int getAutoResizeMode()
    {
        return autoResizeMode;
    }
    
    /**
     * resizes width of all columns based on width of data
     */
    protected void sizeColumnsByData()
    {
        if(!isInitialized)
            return;
		
		TableColumnModel tcm = getColumnModel();
		int columnCount = tcm.getColumnCount();
        if(getRowCount() > 0)
		{
			for(int i = 0; i < columnCount; i++)
			{
			    sizeColumnByData(i);
			}
		}
		else
		{
			sizeColumnByData(columnCount - 1);
		}
		repaintHeader();
		repaintTable();
    }
    
    /**
     * resizes width of a single column based on width of data
     */
    protected void sizeColumnByData(int col)
    {
        if(!isInitialized) 
            return;
        
        TableColumnModel tcm = getColumnModel();
        TableColumn column = tcm.getColumn(col);
		if(!column.getResizable())
			return;
		
        int newWidth = 0;
        int preferredWidth = 0;
        int rowWidthScanCount = Math.min(ROWS_TO_SCAN, getRowCount()); // TODO: scan rows currently shown
        TableCellRenderer hr = column.getHeaderRenderer();
        if(hr == null)
            return;
        
        Component c = hr.getTableCellRendererComponent(this, column.getHeaderValue(), false, false, -1, col);
        newWidth = (int)c.getPreferredSize().width;
		int columnCount = tcm.getColumnCount();
		if(col != columnCount - 1) // last column
		{
			if(this.enableClientSideSorting != false)
			{
			    newWidth += TextHeaderRenderer.ascendingIcon.getIconWidth();
			    newWidth += 5; // gap between icon and text
			}
			for(int row=0; row < rowWidthScanCount; row++)
			{
			    TableCellRenderer r = getCellRenderer(row, col);
			    c = r.getTableCellRendererComponent(this, getValueAt(row, col), false, false, row, col);
			    preferredWidth = (int)c.getPreferredSize().width;
			    if(preferredWidth > newWidth)
			        newWidth = preferredWidth;
			}
			newWidth /= COLUMN_WIDTH_MULTIPLE;
			newWidth++;
			newWidth *= COLUMN_WIDTH_MULTIPLE;
			newWidth = Math.min(column.getMaxWidth(), newWidth);
			newWidth = Math.max(column.getMinWidth(), newWidth);
		}
		else
		{
			int tableWidth = getSize().width;
            Component parent = getParent();
            if (parent != null) {
                tableWidth = parent.getSize().width;
                Debug.println("Table.sizeColumnsByData: table parent width=" + tableWidth);
            }
			int columnWidth = 0;
			for(int i = 0; i < columnCount - 1; i++)
			{
				columnWidth += tcm.getColumn(i).getPreferredWidth();
			}
			newWidth = Math.max(column.getMinWidth(), tableWidth - columnWidth);
		}
        column.setPreferredWidth(newWidth);
        column.setWidth(newWidth);
    }

    private void repaintHeader()
    {
        JTableHeader header = getTableHeader();
        header.validate();
        header.repaint();
        
    }
        
    private void repaintTable()
    {
        validate();
        repaint();
    }
        
    class HeaderMouseListener extends MouseAdapter
    {
        Object lastColIdentifier = null;
        boolean ascending = true;
                
        public void mouseClicked(MouseEvent e) 
        {
            if (e.getClickCount() == 1) 
            {
                int resizingColumn = getResizingColumn(e.getPoint());
                if(resizingColumn != -1)
                {
                    sizeColumnByData(resizingColumn);
                    repaintHeader();
                    repaintTable();
                    return;
                }


                if(enableClientSideSorting == false) {
                    Debug.println("Table.mouseClicked: clientSideSorting=" + enableClientSideSorting);
                    return;
                }

                TableColumnModel columnModel = getColumnModel();
                int viewColumnIndex = columnModel.getColumnIndexAtX(e.getX()); 
                if(viewColumnIndex == -1)
                    return;
                
                TableColumn tableColumn = columnModel.getColumn(viewColumnIndex);

                if(tableColumn.getIdentifier().equals(lastColIdentifier))
                {
                    ascending = !ascending;
                }
                else
                {
                    if(lastColIdentifier != null)
                    {
                        int lastColIndex = columnModel.getColumnIndex(lastColIdentifier);
                        TableColumn lastTableColumn = columnModel.getColumn(lastColIndex);
                        if(lastTableColumn != null)
                        {
                            TableCellRenderer renderer = lastTableColumn.getHeaderRenderer();
                            if(renderer instanceof TextHeaderRenderer)
                            {
                                TextHeaderRenderer r = (TextHeaderRenderer)renderer;
                                r.hideSortIndicator();
                            }
                        }
                    }
                }
                lastColIdentifier = tableColumn.getIdentifier();

                TableCellRenderer renderer = tableColumn.getHeaderRenderer();
                if(renderer instanceof TextHeaderRenderer)
                {
                    TextHeaderRenderer r = (TextHeaderRenderer)renderer;
                    r.showSortIndicator(ascending);
                }
                
                int columnIndex = convertColumnIndexToModel(viewColumnIndex); 
                if(columnIndex != -1) {
                    TableModel tm = getModel();
                    ISortableTableModel sm = (ISortableTableModel)tm;
                    sm.sortByColumn(columnIndex, ascending);
                }
                repaintHeader();
                repaintTable();
            }
        }

        // This method is from BasicTableHeaderUI.  It is used
        // to determine if the mouse click occured in a column 
        // resizing area: +/- 3 pixels from right edge
        private int getResizingColumn(Point p) 
        {
            int column = 0;
            JTableHeader header = getTableHeader();
            Rectangle resizeRect = new Rectangle(-3, 0, 6, header.getSize().height);
            int columnMargin = header.getColumnModel().getColumnMargin();
            Enumeration enumeration = header.getColumnModel().getColumns();

            while (enumeration.hasMoreElements()) {
                TableColumn aColumn = (TableColumn)enumeration.nextElement();
                resizeRect.x += aColumn.getWidth() + columnMargin;

                if (resizeRect.x > p.x) 
                {
                    // Don't have to check the rest, we already gone past p
                    break;
                }
                if (resizeRect.contains(p))
                    return column;

                column++;
            }
            return -1;
        }
    } // class HeaderMouseListener}
}

class TextHeaderRenderer extends JButton implements TableCellRenderer
{
	static ImageIcon checkBoxIcon = new RemoteImage("com/netscape/management/client/components/images/checkHeader.gif");
    static ImageIcon ascendingIcon = new RemoteImage("com/netscape/management/client/components/images/ascending.gif");
    static ImageIcon descendingIcon = new RemoteImage("com/netscape/management/client/components/images/descending.gif");
    boolean isSortable = false;
	boolean isSortVisible = false;
	boolean isSortAscending = false;
    
    public TextHeaderRenderer()
    {
        setHorizontalAlignment(SwingConstants.LEFT);
        setHorizontalTextPosition(SwingConstants.LEFT);
        setBorder(new FlatBorder());
        setFocusPainted(false);
    }

    public TextHeaderRenderer(int alignment, boolean isSortable)
    {
        this();
        this.isSortable = isSortable;
        setHorizontalAlignment(alignment);
        if(alignment == SwingConstants.RIGHT)
            setHorizontalTextPosition(alignment);
        if(isSortable)
        {
            setBorder(new ClickBorder());
        }
    }
    
    public void showSortIndicator(boolean isAscending)
    {
		isSortVisible = true;
		isSortAscending = isAscending;
        setIcon(isAscending ? ascendingIcon : descendingIcon);
    }

    public void hideSortIndicator()
    {
		isSortVisible = false;
        setIcon(null);
    }
    
	public boolean isFocusTraversable()
    { 
        return false; 
    }
    
    public Component getTableCellRendererComponent(JTable table, Object value,
					    boolean isSelected, boolean hasFocus, 
					    int row, int column)
    {
		if(table.getColumnClass(column) == Boolean.class)
		{
			setText("");
            setIcon(checkBoxIcon);
		}
		else
        if(value instanceof String)
		{
            setText((String)value);
			if(isSortVisible)
			{
				showSortIndicator(isSortAscending);
			}
			else
			{
				setIcon(null);
			}
		}
        return this;
    }
}


class TableCheckBoxRenderer implements TableCellRenderer
{
	private static boolean hasSetBorderPaintedFlat = true;
	
    public Component getTableCellRendererComponent(JTable table, Object value,
					    boolean isSelected, boolean hasFocus, 
					    int row, int column)
    {
        if(value instanceof JCheckBox)
        {
            JCheckBox cb = (JCheckBox)value;
            /*try
            {
				if(hasSetBorderPaintedFlat)
					setBorderPaintedFlat(true);
            }
            catch(NoSuchMethodException e)
            {
                // ignore exception.  likely running JDK < 1.3
                // which does not have this method.
				hasSetBorderPaintedFlat = false;
            }*/
            //setText(((JCheckBox)value).getText());
            //setSelected(isSelected);
            
            cb.setOpaque(false);
            cb.setFocusPainted(false);
            // cb.setBorderPaintedFlat(false); 
            cb.setBorder(BorderFactory.createEmptyBorder(0,5,0,0));
            return cb;
        }
        
        return new JCheckBox();
    }
}


class TableCheckBoxEditor implements TableCellEditor
{
    Object value = null;
    
    public Component getTableCellEditorComponent(JTable table,
                                             Object value,
                                             boolean isSelected,
                                             int row,
                                             int column)
    {
        this.value = value;
        if(value instanceof JCheckBox)
        {
            JCheckBox cb = (JCheckBox)value;
            cb.setSelected(isSelected);
            cb.setOpaque(false);
            cb.setFocusPainted(false);
            // cb.setBorderPaintedFlat(false); 
            cb.setBorder(BorderFactory.createEmptyBorder(0,5,0,0));
            return cb;
        }
        return new JCheckBox();
    }
    
    public void addCellEditorListener(CellEditorListener l)
    {
    };
    
    public void cancelCellEditing()
    {
    };
    
    public Object getCellEditorValue()
    {
        return value;
    };
    
    public boolean isCellEditable(EventObject anEvent)
    {
        return true;
    };
    
    public void removeCellEditorListener(CellEditorListener l)
    {
    };
    
    public boolean shouldSelectCell(EventObject anEvent)
    {
        return false;
    };
    
    public boolean stopCellEditing()
    {
        return true;
    };
}

class TableLabelRenderer extends JLabel implements TableCellRenderer
{
    Font defaultFont;
    
	public TableLabelRenderer()
	{
        defaultFont = getFont();
		setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 0));
	}
	
    public Component getTableCellRendererComponent(JTable table, Object value,
					    boolean isSelected, boolean hasFocus, 
					    int row, int column)
    {
        if(value instanceof JLabel)
        {
            JLabel label = (JLabel)value;
            setIcon(label.getIcon());
            setFont(label.getFont());
            setText(label.getText());
        }
		else
		{
            setFont(defaultFont);
            setIcon(null);
			if(value != null)
				setText(value.toString());
			else
				setText("");
		}
		if(isSelected)
		{
			setBackground(table.getSelectionBackground());
			setForeground(table.getSelectionForeground());
			setOpaque(true);
		}
		else
		{
			setBackground(table.getBackground());
			setForeground(table.getForeground());
			setOpaque(false);
		}
        return this;
    }
}
