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

import java.awt.Component;
import java.awt.Cursor;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.ModalDialogUtil;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.nmclf.SuiOptionPane;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPSortKey;
import netscape.ldap.controls.LDAPSortControl;
import netscape.ldap.controls.LDAPVirtualListControl;
import netscape.ldap.controls.LDAPVirtualListResponse;


/**
 * VLDirectoryTableModel is the model for the search results table. It handles
 * virtual list view controls if the LDAP server supports it. The underlying
 * data is a vector of LDAPEntry objects. The displayed data is gathered by
 * looking up the values of the attributes from these LDAPEntry objects. The
 * attributes are specified by the column headers.
 *
 * @see SearchResultPanel
 * @see VLDirectoryTable
 */
public class VLDirectoryTableModel extends AbstractTableModel {
    static final String EMPTY_STRING = "";

    private ResourceSet _resource;
    private RemoteImage _userIcon;
    private RemoteImage _groupIcon;
    private RemoteImage _ouIcon;
    private int _maxResults;
    private Vector _header;
    private Vector _columnName;
    private boolean _useVirtualList;

    // virtual list varibles
    private LDAPConnection _ldc;
    protected LDAPControl _pageControls[];
    protected LDAPVirtualListControl _vlc;
    private LDAPSearchResults _currentSearch;
    private Vector _entries;
    private Vector _LDAPEntries;
    protected boolean _isInitialized;
    private String _baseDN;
    private int _scope;
    private String _filter;
    protected int _beforeCount;
    protected int _afterCount;
    private int _pageSize;
    protected int _size;
    private int _top;
    private int _selectedIndex;
    private JFrame _activeFrame;

    // Controls used by readEntry() method; See browseDNList();
    LDAPControl[] _readEntryControls;

    /**
     * Constructor requires two vectors.
     *
     * @param columnIdentifier  vector of LDAP attributes to be displayed
     * @param columnName        vector of friendly names for the attributes to display
     */
    public VLDirectoryTableModel(Vector columnIdentifier,
            Vector columnName) {
        // Initialize data members
        _resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");
        _maxResults =
                Integer.parseInt(_resource.getString("SearchResult", "MaxResults"));
        _userIcon = new RemoteImage("com/netscape/management/nmclf/icons/user.gif");
        _groupIcon = new RemoteImage("com/netscape/management/nmclf/icons/group.gif");
        _ouIcon = new RemoteImage("com/netscape/management/nmclf/icons/ou.gif");
        _header = columnIdentifier;
        _columnName = columnName;
        _ldc = null;
        _vlc = null;
        _entries = new Vector();
        _LDAPEntries = new Vector();
        _isInitialized = false;
        _pageControls = null;
        _baseDN = null;
        _filter = null;
        _beforeCount = 0;
        _afterCount = 0;
        _pageSize = 10;
        _size = -1;
        _top = 0;
        _selectedIndex = 1;
        _isInitialized = false;
        _useVirtualList = false;
    }


    /**
      * Changes the table columns.
      *
      * @param columnAttributes    vector of LDAP attributes to be displayed
      * @param columnDisplayNames  vector of friendly names for the attributes to display
      */
    public void setColumnInfo(Vector columnAttributes,
            Vector columnDisplayNames) {
        _header = columnAttributes;
        _columnName = columnDisplayNames;
        fireTableStructureChanged();

        // Need to update all rows
        _entries.removeAllElements();
        Enumeration entries = _LDAPEntries.elements();
        LDAPEntry entry = null;
        while (entries.hasMoreElements()) {
            entry = (LDAPEntry) entries.nextElement();
            _entries.addElement(getRow(entry));
        }
        fireTableDataChanged();
    }


    /**
      * Returns the maximum number of results allowed. Only appropriate if
      * searching on version 3.x directory servers since they do not support
      * virtual list search.
      *
      * @return  the maximum number of results allowed
      */
    public int getMaxResults() {
        return _maxResults;
    }


    /**
      * Sets the maximum number of results allowed. Only appropriate if
      * searching on version 3.x directory servers since they do not support
      * virtual list search.
      *
      * @param maxResults  the maximum number of results allowed
      */
    public void setMaxResults(int maxResults) {
        _maxResults = maxResults;
    }


    /**
      * Method called when search has been cancelled. This allows the table
      * model to clean up its operation.
      */
    public void cancelSearch() {
        _useVirtualList = false;

        Debug.println("CancelSearch ldc=" +_ldc + " res=" + _currentSearch);
        if (_ldc != null) {
            try {
                _ldc.abandon(_currentSearch);
            }
            catch (Exception ignore) {}
        }

        fireTableDataChanged(); // Need to update the data count just in case.
        if (_activeFrame != null) {
            _activeFrame.setCursor(
                    Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }


    /**
      * Returns the number of rows managed by the model. Called by JTable.
      *
      * @return an integer indicating the number of rows managed by the model.
      */
    public int getRowCount() {
        if (_useVirtualList == true) {
            return Math.max(0, _size);
        }
        return Math.max(_LDAPEntries.size(), _entries.size());
    }


    /**
      * Gets a page full of data starting at the specified index.
      *
      * @param first  the integer index from which to return.
      * @return       true if succeeded; false otherwise
      */
    private boolean getPage(int first) {
        // Get a full buffer, if possible
        int offset = first - _beforeCount;
        if (offset < 0) {
            first -= offset;
        }
        _vlc.setRange(first, _beforeCount, _afterCount);
        return getPage();
    }


    /**
      * Gets a page full of data using parameters previously set.
      *
      * @return  true if succeeded; false otherwise
      */
    private boolean getPage() {
        Cursor savedCursor = null;

        if (_activeFrame != null) {
            savedCursor = _activeFrame.getCursor();
            _activeFrame.setCursor(
                    Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        }

        //long startTime = System.currentTimeMillis();
        boolean rc = getEntries();
        //long endTime = System.currentTimeMillis();

        //Debug.println("TRACE VLDirectoryTableModel.getPage: elapsed time = " + (endTime - startTime) + " msec");

        if (_activeFrame != null && savedCursor != null) {
            _activeFrame.setCursor(savedCursor);
        }

        if (rc == false) {
            Debug.println("VLDirectoryTableModel.getPage: get entries failed");
            _size = _entries.size(); // Set it to the size of the vector.
            _selectedIndex = 1;
            _top = 0;
            _vlc.setListSize(_size);
            return false;
        }

        LDAPControl[] c = _ldc.getResponseControls();
        if (c == null) {
            Debug.println("TRACE VLDirectoryTableModel.getPage: null response controls");
            _size = _entries.size(); // Set it to the size of the vector.
            _selectedIndex = 1;
            _top = 0;
            _vlc.setListSize(_size);
            return false;
        }
        LDAPVirtualListResponse nextCont =
                LDAPVirtualListResponse.parseResponse(c);
        if (nextCont == null) {
            Debug.println("TRACE VLDirectoryTableModel.getPage: null virtual list response control");
            _size = _entries.size(); // Set it to the size of the vector.
            _selectedIndex = 1;
            _top = 0;
            _vlc.setListSize(_size);
            return false;
        } else {
            _selectedIndex = nextCont.getFirstPosition() - 1;
            Debug.println(
                    "VLDirectoryTableModel.getPage: _selectedIndex = " +
                    _selectedIndex);
            _top = (_selectedIndex > _beforeCount) ?
                    _selectedIndex - _beforeCount : 0;
            Debug.println("VLDirectoryTableModel.getPage: _top = " + _top);
            _size = nextCont.getContentCount();
            int sizeofEntries = _entries.size();
            Debug.println(
                    "VLDirectoryTableModel.getPage: _entries size = " +
                    sizeofEntries);
            if (_size < sizeofEntries) {
                _size = sizeofEntries;
            }
            Debug.println("VLDirectoryTableModel.getPage: _size = " +
                    _size);
            _vlc.setListSize(_size);
        }
        return true;
    }


    /**
      * Performs the actual virtual list search using parameters previously set.
      *
      * @return  true if succeeded; false otherwise
      */
    private boolean getEntries() {
        if (_ldc == null) {
            Debug.println("ERROR VLDirectoryTableModel.getEntries: no LDAP connection");
            return false;
        }

        LDAPSearchConstraints constraints = _ldc.getSearchConstraints();
        if (_pageControls == null) {
            Debug.println("ERROR VLDirectoryTableModel.getEntries: no page controls");
            return false;
        } else {
            // Specify necessary controls for vlv
            constraints.setServerControls(_pageControls);
        }

        _entries.removeAllElements();
        _LDAPEntries.removeAllElements();

        try {
            LDAPSearchResults result = _currentSearch =
                    _ldc.search(_baseDN, _scope, _filter, null, false,
                    constraints);
            LDAPEntry entry = null;
            while (result.hasMoreElements()) {
                Object o = result.next();
                if (o instanceof LDAPEntry) {
                    entry = (LDAPEntry) o;
                    _entries.addElement(getRow(entry));
                    _LDAPEntries.addElement(entry);
                }
            }
            // Causes infinite loops in certain cases, such as when vlv access
            // does not match the search domain access. In these situations,
            // vlv search will return the number of entries that match a
            // particular search filter, regardless of whether the user doing
            // the search has access to those items. However, only items that
            // are actually accessible by the user is returned, causing an
            // inconsistency between the number of items available to the user.
            //fireTableDataChanged();
        }
        catch (LDAPException e) {
            Debug.println("RESULT CODE       : " + e.getLDAPResultCode());
            Debug.println("LDAP ERROR MESSAGE: " + e.getLDAPErrorMessage());
            if (e.getLDAPResultCode() == LDAPException.PROTOCOL_ERROR) {
                showMessageDialog(_activeFrame,
                        _resource.getString("SearchError", "WrongLang"),
                        _resource.getString("SearchError", "Title"),
                        JOptionPane.ERROR_MESSAGE);

            } else if (e.getLDAPResultCode() == LDAPException.ADMIN_LIMIT_EXCEEDED) {
                showMessageDialog(_activeFrame,
                        _resource.getString("SearchError", "AdminLimitExceeded"),
                        _resource.getString("SearchError", "Incomplete"),
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                showMessageDialog(_activeFrame,
                        _resource.getString("SearchError", "General") + e,
                        _resource.getString("SearchError", "Title"),
                        SuiOptionPane.ERROR_MESSAGE);
                /*System.out.println("ERROR getting entries: LDAPException: " + e);
                switch(e.getLDAPResultCode())
            {
                case LDAPException.UNAVAILABLE_CRITICAL_EXTENSION:
                    System.out.println("--> Probable cause: stale server control. Try searching again.");
                    break;
                case LDAPException.UNAVAILABLE:
                    System.out.println("--> Probable cause: server went down. Try restarting the directory server.");
                    break;
            };*/
            }
            return false;
        }

        return true;
    }

    private LDAPEntry readEntry(String dn) {
        if (_ldc == null || !_ldc.isConnected()) {
            Debug.println("ERROR VLDirectoryTableModel.readEntry: no LDAP connection");
            return null;
        }

        LDAPSearchConstraints constraints = _ldc.getSearchConstraints();
        constraints.setServerControls(_readEntryControls);
        try {
            return  _ldc.read (dn, constraints);
        }
        catch (LDAPException e) {
            Debug.println("readEntry " + dn + " " + e);
        }
        return null;
    }

    /**
      * Get a row of data from the LDAPEntry object. The row is made up of
      * the attribute values specified in the column headers.
      *
      * @param entry  the LDAP entry to retrieve the row values from
      * @return       an array of String objects representing the row
      */
    private Object [] getRow(LDAPEntry entry) {
        boolean isOU = false;
        boolean isUser = false;
        boolean isGroup = false;

        boolean isValidEntry = entry.getAttributeSet().size() > 0;

        try {
            if (entry.getAttribute("cn") == null) {
                isOU = true;
            }

            if (isOU == false) {
                String objectClasses = LDAPUtil.flatting(
                        entry.getAttribute("objectclass",
                        LDAPUtil.getLDAPAttributeLocale())).toLowerCase();
                if (objectClasses != null &&
                        objectClasses.indexOf("person") != -1) {
                    isUser = true;
                }
            }

            if (isOU == false && isUser == false) {
                String objectClasses = LDAPUtil.flatting(
                        entry.getAttribute("objectclass",
                        LDAPUtil.getLDAPAttributeLocale())).toLowerCase();
                if (objectClasses != null &&
                        objectClasses.indexOf("groupofuniquenames") != -1) {
                    isGroup = true;
                }
            }
        } catch (Exception e) {
            isValidEntry = false;
            isUser = true;
        }

        Enumeration headings = _header.elements();
        Object rowInfo[] = new Object[_header.size()];
        String heading;
        for (int i = 0; headings.hasMoreElements(); i++) {
            heading = (String) headings.nextElement();
            if (isValidEntry) {
                if (heading.equals("cn")) {
                    if (isUser) {
                        JLabel cellInfo = new JLabel();
                        cellInfo.setIcon(_userIcon);
                        cellInfo.setText( LDAPUtil.flatting(
                                entry.getAttribute(heading,
                                LDAPUtil.getLDAPAttributeLocale())));
                        rowInfo[i] = cellInfo;
                    } else if (isGroup) {
                        JLabel cellInfo = new JLabel();
                        cellInfo.setIcon(_groupIcon);
                        cellInfo.setText( LDAPUtil.flatting(
                                entry.getAttribute(heading,
                                LDAPUtil.getLDAPAttributeLocale())));
                        rowInfo[i] = cellInfo;
                    } else if (isOU) {
                        JLabel cellInfo = new JLabel();
                        cellInfo.setIcon(_ouIcon);
                        cellInfo.setText( LDAPUtil.flatting(
                                entry.getAttribute("ou" ,
                                LDAPUtil.getLDAPAttributeLocale())));
                        rowInfo[i] = cellInfo;
                    }
                } else {
                    rowInfo[i] = LDAPUtil.flatting(
                            entry.getAttribute(heading,
                            LDAPUtil.getLDAPAttributeLocale()));
                }
            } else {
                if (i == 0) {
                    rowInfo[i] = entry.getDN();
                } else {
                    rowInfo[i] = "";
                }
            }
        }
        return rowInfo;
    }


    /**
      * Sets the message in the cn column. If the cn column is unavailable,
      * display in the second column. Note that columns are moveable.
      *
      * @param message  the message to set
      * @return          an array of String objects representing the row
      */
    private Object [] getRow(String message) {
        Object rowInfo[] = new Object[_header.size()];
        for (int i = 0; i < rowInfo.length; i++) {
            rowInfo[i] = null;
        }
        int cnIndex = _header.indexOf("cn");
        if (cnIndex != -1) {
            // Whenever possible, display under the cn column.
            rowInfo[cnIndex] = message;
        } else {
            // If the cn column is unavailable, display in the first column.
            rowInfo[0] = message;
        }
        return rowInfo;
    }

    /**
     * This method is used for listing static group members. The list of user DNs
     * id already known, but each entry needs to be read individually in order
     * to get required attributes.
     *
     * Initialize _LDAPEntries Vector with LDAPEntries containing only DNs.
     * Later, when getValueAt() is called, read the actual entry.
     */
    void browseDNList(LDAPConnection ldc, Vector dnList) {
        _useVirtualList = false;
        _ldc = ldc;
         _LDAPEntries.setSize(dnList.size());
        _entries.setSize(dnList.size());

        _readEntryControls = new LDAPControl[1];
        _readEntryControls[0] = new LDAPControl( LDAPControl.MANAGEDSAIT, true, null );

        for (int i=0; i < dnList.size(); i++) {
            String dn = (String)dnList.elementAt(i);
            _LDAPEntries.setElementAt(new LDAPEntry(dn), i);
        }
        fireTableDataChanged();
    }

    /**
      * Adds the new entry to the row. Disables virtual list.
      *
      * @param entry  an LDAPEntry object to add
      */
    public void addRow(LDAPEntry entry) {
        if (_useVirtualList == true) {
            _LDAPEntries.removeAllElements();
            _entries.removeAllElements();
            _useVirtualList = false;
        }
        if ((_entries.size() == 1) && (_LDAPEntries.size() == 0)) {
            _entries.removeAllElements();
        }
        _entries.addElement(getRow(entry));
        _LDAPEntries.addElement(entry);
        fireTableDataChanged();
    }


    /**
      * Adds the new message to the first row. Disables virtual list.
      *
      * @param message  String text to add
      */
    public void addRow(String message) {
        if (_useVirtualList == true) {
            _LDAPEntries.removeAllElements();
            _entries.removeAllElements();
            _useVirtualList = false;
        }
        if ((_entries.size() == 1) && (_LDAPEntries.size() == 0)) {
            _entries.removeAllElements();
        }
        _entries.addElement(getRow(message));
        fireTableDataChanged();
    }


    /**
      * Replace entry in row with LDAPEntry specified.
      *
      * @param row    row to be replaced
      * @param entry  replace with this entry
      */
    public void replaceRow(LDAPEntry entry, int row) {
        _LDAPEntries.setElementAt(entry, row);
        _entries.setElementAt(getRow(getRow(row)), row);
        fireTableDataChanged();
    }


    /**
      * Retrieves the number of columns in the table.
      *
      * @return  the number of columns in the table
      */
    public int getColumnCount() {
        return _header.size();
    }


    /**
      * Retrieves the name of the indicated column.
      *
      * @param columnIndex  the column whose name is to be retrieved
      * @return             the name for the column
      */
    public String getColumnName(int columnIndex) {
        return(columnIndex >= 0 && columnIndex < _columnName.size()) ?
                (String)(_columnName.elementAt(columnIndex)) : "";
    }


    /**
      * Retrieves the value at the indicated row and column.
      *
      * @param rowIndex     the row at which the desired value resides
      * @param columnIndex  the column at which the desired value resides
      * @return             the desired value
      */
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (_useVirtualList) {
            if ((rowIndex < _top) || (rowIndex >= _top + _entries.size())) {
                if (getPage(rowIndex) == false) {
                    return null;
                }
            }
            int offset = rowIndex - _top;
            if ((offset < 0) || (offset >= _entries.size())) {
                return null;
            } else {
                Object[] tmp = (Object[])_entries.elementAt(offset);
                return tmp[columnIndex];
            }

        } else {
            Object row[] = null;
            LDAPEntry entry = null;
            // if the size of _entries and _LDAPEntries is less than the row #
            // to display, no values need to be retrieved.
            // [blackflag 624252] if search returned 0 entries,
            // _LDAPEntries.elementAt(rowIndex) issues
            // ArrayIndexOutOfBoundsException.
            if (_entries.size() > rowIndex) {
                row = (Object[])_entries.elementAt(rowIndex);
            }
            if (_LDAPEntries.size() > rowIndex) {
                entry = (LDAPEntry)_LDAPEntries.elementAt(rowIndex);
            }
            if (row  == null && entry != null) {
                //  Entry not yet loaded, _LDAPEntries was set from browseDNList().
                String dn = entry.getDN();
                entry = readEntry(dn);
                if (entry == null) {
                    entry = new LDAPEntry(dn);
                }
                 row = getRow(entry);
                _entries.setElementAt(row, rowIndex);
                _LDAPEntries.setElementAt(entry, rowIndex);
            }
            if ((row != null) && (columnIndex < row.length)) {
                return row[columnIndex];
            } else {
                return null;
            }
        }
    }


    /**
      * Retrieves the index of the selected row.
      *
      * @return  the index of the selected row
      */
    public int getSelectedIndex() {
        return _selectedIndex;
    }


    /**
      * Retrieves the first index.
      *
      * @return  the first index
      */
    public int getFirstIndex() {
        return _top;
    }


    /**
      * Sets the number of rows that are visible in the table.
      *
      * @param size  the number of rows that are visible
      */
    public void setPageSize(int size) {
        _pageSize = size;
    }


    /**
      * Retrieves the LDAPEntry object at the indicated row index.
      *
      * @return  the LDAPEntry object for row
      */
    public LDAPEntry getRow(int index) {
        if (_useVirtualList == true) {
            if ((index < _top) || (index >= _top + _entries.size())) {
                if (getPage(index) == false) {
                    return null;
                }
            }
            int offset = index - _top;
            if ((offset < 0) || (offset >= _entries.size())) {
                return null;
            } else {
                return(LDAPEntry)_LDAPEntries.elementAt(offset);
            }
        } else {
            // This supports the case where a message such as "Nothing found"
            // was added to the list AFTER a search.
            if (_LDAPEntries.size() == 0) {
                return null;
            }
            return(LDAPEntry)_LDAPEntries.elementAt(index);
        }
    }


    /**
      * Convenience routine to test the connection to the LDAP server and
      * attempt to connect if down.
      *
      * @param ldc  the connection to the LDAP server
      */
    private boolean isConnected(LDAPConnection ldc) {
        try {
            if (ldc == null) {
                return false;
            }
            if (ldc.isConnected() == false) {
                ldc.connect(LDAPUtil.LDAP_VERSION, ldc.getHost(),
                        ldc.getPort(), ldc.getAuthenticationDN(),
                        ldc.getAuthenticationPassword());
            }
            return ldc.isConnected();
        } catch (LDAPException e) {
            Debug.println(
                    "VLDirectoryTableModel.isConnected: Could not connect to LDAP server: " + e);
            return false;
        }
    }


    /**
      * @deprecated  Replaced by doSearch(LDAPConnection,String,int,String)
      * @see  #doSearch(LDAPConnection,String,int,String)
      */
    @Deprecated
    public void doSearch(LDAPConnection ldc, String baseDN, String filter) {
        doSearch(ldc, baseDN, LDAPConnection.SCOPE_SUB, filter);
    }


    /**
      * Initiates the search for the specified query.
      *
      * @param ldc     the connection to the LDAP server
      * @param baseDN  the search base DN
      * @param scope   the search scope
      * @param filter  the search string
      */
    public void doSearch(LDAPConnection ldc, String baseDN, int scope,
            String filter) {
        // Disconnect previous search
        if (_ldc != null && _ldc.isConnected()) {
            try {
                _ldc.disconnect();
                _ldc = null;
            } catch (LDAPException e) {

            }
        }

        if (isConnected(ldc)) {
            _ldc = (LDAPConnection) ldc.clone();
        } else {
            showMessageDialog(null,
                    _resource.getString("SearchError","NoConnection"),
                    _resource.getString("SearchError","Title"),
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        _baseDN = baseDN;
        _scope = scope;
        _filter = filter;
        _isInitialized = false; // need to reset for every search for getRowCount()
        _useVirtualList = false;
        _activeFrame = UtilConsoleGlobals.getActivatedFrame();

        LDAPSearchConstraints constraints = _ldc.getSearchConstraints();
        constraints.setMaxResults(_maxResults);


        String vlvSort="cn";
        vlvSort = LDAPUtil.getVLVIndex(_ldc, _baseDN, _scope,
                                       _filter, vlvSort);
        Debug.println("VLDirectoryTableModel: getVlVIndex="+vlvSort);

        if (vlvSort != null) {
            _beforeCount = _pageSize * 2;
            _afterCount = _pageSize * 2;
            _pageControls = new LDAPControl[2];

            StringTokenizer st = new StringTokenizer(vlvSort, " ");
            LDAPSortKey[] keys = new LDAPSortKey[st.countTokens()];
            for (int i=0; st.hasMoreTokens(); i++) {
                keys[i] = new LDAPSortKey(st.nextToken());
            }

            _pageControls[0] = new LDAPSortControl(keys, true);
            _vlc = new LDAPVirtualListControl("A", _beforeCount,
                    _afterCount);
            _pageControls[1] = _vlc;
            getPage(0);
            _useVirtualList = true;
            fireTableDataChanged();
        } else {
            LDAPSearchResults result;
            int count = 0;
            Object element;

            try {
                result = _currentSearch = _ldc.search(_baseDN, _scope, _filter, null,
                        false, constraints);
                while (result.hasMoreElements() && count < _maxResults) {
                    element = result.next();
                    if (element instanceof LDAPEntry) {
                        addRow((LDAPEntry) element);
                        count++;
                    }
                }
            } catch (LDAPException e) {
                if (e.getLDAPResultCode() == LDAPException.PROTOCOL_ERROR) {
                    showMessageDialog(null,
                            _resource.getString("SearchError", "WrongLang"),
                            _resource.getString("SearchError",
                            "Title"), JOptionPane.ERROR_MESSAGE);
                } else if (e.getLDAPResultCode() ==
                        LDAPException.NO_SUCH_OBJECT) {
                    // check whether the login user exist or not
                    try {
                        LDAPEntry authDN =
                                _ldc.read(_ldc.getAuthenticationDN());
                    } catch (LDAPException eNoObject) {
                        if (eNoObject.getLDAPResultCode() ==
                                LDAPException.NO_SUCH_OBJECT) {
                            String str = MessageFormat.format(
                                    _resource.getString("SearchError",
                                    "WrongDN"),
                                    new Object[] {_ldc.getAuthenticationDN()});
                            showMessageDialog(null, str,
                                    _resource.getString("SearchError",
                                    "Title"), JOptionPane.ERROR_MESSAGE);
                        } else {
                            showMessageDialog(null,
                                    _resource.getString("SearchError",
                                    "General") + e,
                                    _resource.getString("SearchError",
                                    "Title"), JOptionPane.ERROR_MESSAGE);
                        }
                    }
                } else {
                    showMessageDialog(null,
                            _resource.getString("SearchError",
                            "General") + e,
                            _resource.getString("SearchError",
                            "Title"), JOptionPane.ERROR_MESSAGE);
                }
                return;
            }

            if (count == _maxResults) {
                String msg = _resource.getString("SearchResult",
                        "MaxResultsMessage1") + _maxResults +
                        _resource.getString("SearchResult", "MaxResultsMessage2");

                showMessageDialog(null, msg,
                        _resource.getString("SearchResult", "DialogTitle"),
                        JOptionPane.INFORMATION_MESSAGE);
                ModalDialogUtil.sleep();
            }

            fireTableDataChanged();
        }
    }


    /**
      * Deletes the specified table row.
      *
      * @param entry  the entry to delete
      */
    public void deleteRow(LDAPEntry entry) {
        int removeIndex = _LDAPEntries.indexOf(entry);
        if (removeIndex != -1) {
            _entries.removeElementAt(removeIndex);
            _LDAPEntries.removeElementAt(removeIndex);
            fireTableRowsDeleted(removeIndex, removeIndex);
        }
    }


    /**
      * @deprecated  Replaced by deleteAllRows()
      * @see  #deleteAllRows()
      */
    @Deprecated
    public void deleteAllRow() {
        deleteAllRows();
    }


    /**
      * Deletes all table rows.
      */
    public void deleteAllRows() {
        _useVirtualList = false;
        _entries.removeAllElements();
        _LDAPEntries.removeAllElements();
        fireTableDataChanged();
    }

    void showMessageDialog(Component parent, final Object msg,
                           final String title, final int msgType) {

        final Component fParent = (parent != null) ?
              parent : UtilConsoleGlobals.getActivatedFrame();

        if (SwingUtilities.isEventDispatchThread()) {
            JOptionPane.showMessageDialog(fParent, msg, title, msgType);
        }
        else {
            try {
                 SwingUtilities.invokeLater(new Runnable() {
                     public void run() {
                         JOptionPane.showMessageDialog(fParent, msg, title, msgType);
                     }
                });
            }
            catch (Exception ignore) {}

        }
    }
}
