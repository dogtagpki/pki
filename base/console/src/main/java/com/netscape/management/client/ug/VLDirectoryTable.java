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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JViewport;
import javax.swing.event.ListSelectionListener;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.preferences.PreferenceManager;
import com.netscape.management.client.preferences.Preferences;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.TableHeaderEditor;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.nmclf.SuiOptionPane;
import com.netscape.management.nmclf.SuiTable;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPObjectClassSchema;
import netscape.ldap.LDAPSchema;


/**
 * VLDirectoryTable is a wrapper over the actual search results table.
 *
 * @see SearchResultPanel
 * @see VLDirectoryTableModel
 */
public class VLDirectoryTable extends JPanel {
    ResourceSet _resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");

    SuiTable _table;
    VLDirectoryTableModel _dataModel;
    JScrollPane _scrollpane;

    JPopupMenu _tableHeaderMenu;
    JMenuItem _customizeMenuItem;

    Hashtable _map;
    Vector _attributes;
    Vector _columnNames;

    ConsoleInfo _ci;
    static String[]_availableAttributes;

    Preferences _prefs;
    private boolean _isColumnCustomizationEnabled = true;

    /**
     * Constructor which takes a reference to an object used to store preferences.
     *
     * @param attrMapping    Mapper that map attribute to a display string
     * @param headerAttr     Attributes that specify how column should be constructed.
     *                        This also determain which attribute should be displayed.
     * @param p              Reference to the preferences object
     */
    public VLDirectoryTable(Hashtable attrMapping, Vector headerAttr,
            Preferences p) {
        this(attrMapping, headerAttr);
        _prefs = p;
    }


    /**
      * Constructor
      *
      * @param attrMapping    Mapper that map attribute to a display string
      * @param headerAttr     Attributes that specify how column should be constructed.
      *                        This also determain which attribute should be displayed.
      */
    public VLDirectoryTable(Hashtable attrMapping, Vector headerAttr) {
        super(true);
        setLayout(new BorderLayout());

        _prefs = null;
        _ci = null;
        _map = attrMapping;

        //this is a what we will display on the header cell
        Vector header = new Vector();
        //header.addElement(""); // type icon
        for (int i = 0; i < headerAttr.size(); i++) {
            Object tmp = attrMapping.get(headerAttr.elementAt(i));
            if (tmp == null) {
                header.addElement(headerAttr.elementAt(i));
            } else {
                header.addElement(tmp);
            }
        }

        _attributes = headerAttr;
        _columnNames = header;
        _dataModel = new VLDirectoryTableModel(headerAttr, header);

        // Create the table
        _table = new SuiTable(_dataModel);
        _table.setColumnSelectionAllowed(false);
        _table.setCellSelectionEnabled(false);
        _table.setRowSelectionAllowed(true);
        _table.setShowGrid(false);
        _table.getTableHeader().addMouseListener(
                new TableHeaderMouseListener());

        _customizeMenuItem =
                new JMenuItem(_resource.getString("TableHeader", "Customize"));
        _customizeMenuItem.addActionListener(
                new TableHeaderActionListener());
        _tableHeaderMenu = new JPopupMenu();
        _tableHeaderMenu.add(_customizeMenuItem);

        for (int i = 0; i < _dataModel.getColumnCount(); i++) {
            switch (i) {
            case 0:
                _table.setColumnWidth(0, 200);
                break;
            case 1:
                _table.setColumnWidth(1, 100);
                break;
            case 2:
                _table.setColumnWidth(2, 200);
                break;
            }
        }

        // Put the table and header into a scrollPane
        _scrollpane = SuiTable.createScrollPaneForTable(_table);

        JViewport mainViewPort = _scrollpane.getViewport();
        mainViewPort.setBackground(Color.white);

        add("Center", _scrollpane);
    }

    /**
     * Checks whether column customization is enabled.
     * @return true if columsn can be customized
     */
    public boolean isColumnCustomizationEnabled()
    {
        return _isColumnCustomizationEnabled;
    }

    /**
     * Sets whether column customization should be enabled.
     * @param b if true, column customization should be allowed
     */
    public void setColumnCustomizationEnabled(boolean b)
    {
        _isColumnCustomizationEnabled = b;
    }


    /**
      * Changes the number of result table columns, its corresponding
      * attributes, and its display names.
      *
      * @param  columnAttributes    the attributes displayed in the columns
      * @param  columnDisplayNames  the column header names
      */
    public void setColumnInfo(Vector columnAttributes,
            Vector columnDisplayNames) {
        if (columnAttributes != null && columnDisplayNames != null) {
            int attrSize = columnAttributes.size();
            int labelSize = columnDisplayNames.size();
            if (attrSize == 0 || attrSize != labelSize) {
                Debug.println("VLDirectoryTable.setColumnInfo: invalid parameters: size of column attributes and labels differ");
                return;
            }
            if (_prefs != null) {
                _prefs.set(SearchResultPanel.PREFERENCE_COLUMN_COUNT,
                        attrSize);
                for (int i = 0; i < attrSize; i++) {
                    _prefs.set(
                            SearchResultPanel.PREFERENCE_COLUMN_ATTRIBUTE_PREFIX +
                            i, (String) columnAttributes.elementAt(i));
                    _prefs.set(
                            SearchResultPanel.PREFERENCE_COLUMN_LABEL_PREFIX +
                            i, (String) columnDisplayNames.elementAt(i));
                }
                PreferenceManager.saveAllPreferences();
            }
            _attributes = columnAttributes;
            _columnNames = columnDisplayNames;
            _dataModel.setColumnInfo(columnAttributes, columnDisplayNames);
        } else {
            Debug.println("VLDirectoryTable.setColumnInfo: invalid parameters: column attributes and/or labels are null");
        }
    }


    /**
      * Gets the maximum number of results that can be retrieved and displayed
      * if using DS 3.x. For DS 4.0 and beyond, virtual list controls obviate
      * the need for this API.
      *
      * @return the maximum number of results allowed
      */
    public int getMaxResults() {
        return _dataModel.getMaxResults();
    }


    /**
      * Sets the maximum number of results that can be retrieved and displayed
      * if using DS 3.x. For DS 4.0 and beyond, virtual list controls obviate
      * the need for this API.
      *
      * @param  maxResults  the maximum number of results allowed
      */
    public void setMaxResults(int maxResults) {
        _dataModel.setMaxResults(maxResults);
    }


    /**
      * Adds a list listener.
      *
      * @param listener  list listener to add
      */
    public void addListSelectionListener(ListSelectionListener listener) {
        _table.getSelectionModel().addListSelectionListener(listener);
    }


    /**
      * Adds a mouse listener.
      *
      * @param listener  mouse listener to add
      */
    public void addTableMouseListener(MouseListener listener) {
        _table.addMouseListener(listener);
    }

    /**
      * @deprecated  Replaced by doSearch(LDAPConnection,String,int,String)
      * @see  #doSearch(LDAPConnection,String,int,String)
      */
    @Deprecated
    public synchronized void doSearch(LDAPConnection ldc,
            String sBaseDN, String filter) {
        doSearch(ldc, sBaseDN, LDAPConnection.SCOPE_SUB, filter);
    }


    /**
      * Need to synchronize access to this method since it is called from a thread.
      * Invokes the LDAP search.
      *
      * @param ldc     the connection to the LDAP server
      * @param baseDN  the base DN to search from
      * @param scope   the search scope
      * @param filter  the search filter
      */
    public synchronized void doSearch(LDAPConnection ldc,
            String baseDN, int scope, String filter) {
        int vpHeight = _scrollpane.getViewport().getViewSize().height;
        int rowHeight = _table.getRowHeight();
        int pageSize = vpHeight / rowHeight;
        if (pageSize < 10) {
            pageSize=30;
        }
        _dataModel.setPageSize(pageSize);
        _dataModel.doSearch(ldc, baseDN, scope, filter);
        if (_dataModel.getRowCount() > 0) {
            _table.setRowSelectionInterval(0, 0); // Select the first item.
        }
    }

    /**
     * Set the list of static group members to be shown in the table
     */
    void browseDNList(Vector dnList) {
        LDAPConnection ldc = _ci.getUserLDAPConnection();
        _dataModel.browseDNList(ldc, dnList);
    }

    /**
      * Add a row to the current table.
      *
      * @param ldapEntry  the entry to add
      */
    public void addRow(LDAPEntry ldapEntry) {
        _dataModel.addRow(ldapEntry);
        int count = _dataModel.getRowCount();
        int lastIndex = count - 1;
        if (lastIndex >= 0) {
            _table.setRowSelectionInterval(lastIndex, lastIndex); // Select the first item.
        }
    }


    /**
      * Add a message row to the current table.
      *
      * @param String  the message to add
      */
    public void addRow(String message) {
        _dataModel.addRow(message);
    }



    /**
      * Replace entry in row with LDAPEntry specified.
      *
      * @param row    row to be replaced
      * @param entry  replace with this entry
      */
    public void replaceRow(LDAPEntry entry, int row) {
        _dataModel.replaceRow(entry, row);
    }

    /**
      * Retrieves all selected indices.
      *
      * @return  the indices of all selected rows, or an empty int array if no row is selected.
      */
    public int[] getSelectedRows() {
        return _table.getSelectedRows();
    }


    /**
      * Retrieves all selected entries.
      *
      * @return  the vector containing all the selected entries.
      */
    public Vector getSelectedEntries() {
        int index[] = _table.getSelectedRows();
        Vector ldapEntries = new Vector();

        // This supports the case where a message such as "Nothing found"
        // was added to the list AFTER a search.
        if (index.length == 1) {
            if (getRow(index[0]) == null) {
                return ldapEntries;
            }
        }

        for (int i = 0; i < index.length; i++) {
            ldapEntries.addElement(getRow(index[i]));
        }
        return ldapEntries;
    }


    /**
      * Retrieves the specified entry.
      *
      * @param index  the entry to retrieve
      * @return       the entry at the specified index, null if index > number of rows
      */
    public LDAPEntry getRow(int index) {
        return _dataModel.getRow(index);
    }


    /**
      * Retrieves the number of rows in the table.
      *
      * @return  the number of rows in the table.
      */
    public int getRowCount() {
        return _dataModel.getRowCount();
    }


    /**
      * Returns the selected row.
      *
      * @return  the index of the last row selected or added to the selection, (lead selection) or -1 if no row is selected.
      */
    public int getSelectedRow() {
        return _table.getSelectedRow();
    }


    /**
      * Returns the number of rows selected.
      *
      * @return the number of rows selected. 0 if no row is selected.
      */
    public int getSelectedRowCount() {
        return _table.getSelectedRowCount();
    }


    /**
      * @deprecated  Replaced by deleteAllRows()
      * @see  #deleteAllRows()
      */
    @Deprecated
    public void deleteAllRow() {
        _dataModel.deleteAllRows();
    }


    /**
      * Deletes all rows from this table.
      */
    public void deleteAllRows() {
        _dataModel.deleteAllRows();
    }


    /**
      * @deprecated  Replaced by deleteRows(int[])
      * @see  #deleteRows(int[])
      */
    @Deprecated
    public void deleteRow(int index[]) {
        deleteRows(index);
    }


    /**
      * Deletes all specified rows from the table.
      *
      * @param index  an array of row indices to delete
      */
    public void deleteRows(int index[]) {
        Vector tmp = new Vector();
        for (int i = 0; i < index.length; i++) {
            tmp.addElement(getRow(index[i]));
        }

        for (int i = 0; i < tmp.size(); i++) {
            _dataModel.deleteRow((LDAPEntry)(tmp.elementAt(i)));
        }
    }


    /**
      * Deletes the specified entries.
      *
      * @param entries  entries to delete
      */
    public void deleteRows(Vector entries) {
        int size = entries.size();
        for (int i = 0; i < size; i++) {
            _dataModel.deleteRow((LDAPEntry)(entries.elementAt(i)));
        }
    }


    /**
      * Returns the row number indicated by the coordinate in the table.
      *
      * @param p  the coordinate in the table
      */
    public int rowAtPoint(Point p) {
        return _table.rowAtPoint(p);
    }


    /**
      * Sets the width of the table column.
      *
      * @param col    the column to set
      * @param width  the new width
      */
    public void setTableColumnWidth(int col, int width) {
        _table.setColumnWidth(col, width);
    }


    /**
      * This calls the clean up method in the data model if the search has
      * been cancelled.
      */
    public void cancelSearch() {
        _dataModel.cancelSearch();
    }


    /**
     * Called from SearchResultPanel, lets this class keep track of the
      * global information necessary for reading the schema information.
     * The schema information needs to be read dynamically to retrieve the
      * attributes for user, group, and ou object classes using
     * the LDAP schema. These attributes are used by the TableHeaderEditor.
     *
     * @param ci      the session information
     */
    public void setConsoleInfo(ConsoleInfo ci) {
        _ci = ci;
    }


    /**
     * Initializes the _availableAttributes static member when the user
      * opts to customize the table columns for the first time.
     *
     * @return  true if initialize succeeded; false otherwise
     */
    private boolean initializeAvailableAttributes() {
        if (_ci == null) {
            Debug.println("VLDirectoryTable: no session info to get schema from");
            return false;
        }

        LDAPSchema schema = null;
        LDAPConnection ldc = _ci.getUserLDAPConnection();
        if ((ldc != null) && (ldc.isConnected())) {
            try {
                /* Get the schema from the Directory */
                schema = new LDAPSchema();
                schema.fetchSchema(ldc);
            } catch (LDAPException e) {
                schema = null;
            }
        }

        if (schema == null) {
            Debug.println("VLDirectoryTable: could not get schema");
            return false;
        }

        Vector allAttributes = new Vector();

        Vector userObjectClasses =
                (Vector) ResourceEditor.getNewObjectClasses().get(
                ResourceEditor.KEY_NEW_USER_OBJECTCLASSES);
        Vector groupObjectClasses =
                (Vector) ResourceEditor.getNewObjectClasses().get(
                ResourceEditor.KEY_NEW_GROUP_OBJECTCLASSES);
        Vector ouObjectClasses =
                (Vector) ResourceEditor.getNewObjectClasses().get(
                ResourceEditor.KEY_NEW_OU_OBJECTCLASSES);

        if (userObjectClasses == null || groupObjectClasses == null ||
                ouObjectClasses == null) {
            Debug.println("VLDirectoryTable: cannot get attributes since one or more objectclasses are null");
            return false;
        }

        getAllAttributesFor(allAttributes, userObjectClasses, schema);
        getAllAttributesFor(allAttributes, groupObjectClasses, schema);
        getAllAttributesFor(allAttributes, ouObjectClasses, schema);

        String[] allAttrStrings = new String[allAttributes.size()];
        allAttributes.copyInto(allAttrStrings);

        _availableAttributes = allAttrStrings;
        return true;
    }


    /**
      * Dynamically retrieves the attributes for user, group, and
      * ou object classes using the LDAP schema.
      *
      * @param result         the Vector to store results into
      * @param objectClasses  the attributes to retrieve for
      * @param schema         the LDAP schema information
      */
    private void getAllAttributesFor(Vector result,
            Vector objectClasses, LDAPSchema schema) {
        Enumeration objectClassEnum = objectClasses.elements();
        while (objectClassEnum.hasMoreElements()) {
            String ocName = (String) objectClassEnum.nextElement();
            LDAPObjectClassSchema objectClassEntry =
                    schema.getObjectClass(ocName);
            Enumeration enumReq = objectClassEntry.getRequiredAttributes();
            Enumeration enumAllow =
                    objectClassEntry.getOptionalAttributes();
            Object attr = null;
            while (enumReq.hasMoreElements()) {
                attr = enumReq.nextElement();
                if (((String) attr).indexOf("binary") != -1) {
                    continue; // skip binaries
                }
                if (result.indexOf(attr) == -1) {
                    result.addElement(attr); // Only add the attribute if not already present
                }
            }
            while (enumAllow.hasMoreElements()) {
                attr = enumAllow.nextElement();
                if (((String) attr).indexOf("binary") != -1) {
                    continue; // skip binaries
                }
                if (result.indexOf(attr) == -1) {
                    result.addElement(attr); // Only add the attribute if not already present
                }
            }
        }
    }


    /**
      * TableHeaderActionListener handles action events on the table header
      * popup menu.
      */
    class TableHeaderActionListener implements ActionListener {
        /**
          * Brings up the column header editor.
          */
        public void actionPerformed(ActionEvent e) {
            if (_isColumnCustomizationEnabled && e.getSource().equals(_customizeMenuItem)) {
                if (_availableAttributes == null) {
                    JFrame frame = UtilConsoleGlobals.getActivatedFrame();
                    if (frame != null) {
                        frame.setCursor( Cursor.getPredefinedCursor(
                                Cursor.WAIT_CURSOR));
                    }
                    if (VLDirectoryTable.this.initializeAvailableAttributes()
                            == false) {
                        SuiOptionPane.showMessageDialog(frame, // if null, SuiOptionPane knows to center on screen
                                _resource.getString("TableHeaderEditor",
                                        "NoSchemaError"),
                                        _resource.getString("TableHeaderEditor",
                                        "ErrorTitle"),
                                        SuiOptionPane.ERROR_MESSAGE);
                    }
                    if (frame != null) {
                        frame.setCursor( Cursor.getPredefinedCursor(
                                Cursor.DEFAULT_CURSOR));
                    }
                }
                if (_availableAttributes != null) {
                    TableHeaderEditor editor = new TableHeaderEditor(
                            UtilConsoleGlobals.getActivatedFrame(),
                            _resource.getString("TableHeaderEditor",
                            "Title"),
                            _resource.getString("TableHeaderEditor",
                            "ListLabel"),
                            _resource.getString("TableHeaderEditor",
                            "TableSelectedLabel"),
                            _resource.getString("TableHeaderEditor",
                            "TableSelectedNameLabel"),
                            _availableAttributes, _attributes,
                            _columnNames);
                    editor.show();
                    if (editor.isCancel()) {
                        return;
                    }
                    Vector attributes = editor.getColumnValues();
                    Vector columnNames = editor.getColumnNames();
                    VLDirectoryTable.this.setColumnInfo(attributes,
                            columnNames);
                }
            }
        }
    }


    /**
      * TableHeaderMouseListener handles mouse events on the table header.
      * In particular, it handles the popup menu trigger events to display
      * the customize option for the table header.
      */
    class TableHeaderMouseListener implements MouseListener {
        public void mouseClicked(MouseEvent e) {
        }

        public void mouseEntered(MouseEvent e) {
        }

        public void mouseExited(MouseEvent e) {
        }

        public void mousePressed(MouseEvent e) {
            if (_isColumnCustomizationEnabled && e.isPopupTrigger()) {
                _tableHeaderMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        }

        public void mouseReleased(MouseEvent e) {
            if (_isColumnCustomizationEnabled && e.isPopupTrigger()) {
                _tableHeaderMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        }
    }
}
