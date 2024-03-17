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
import java.awt.Frame;
import java.awt.Point;
import java.awt.event.ActionListener;
import java.awt.event.MouseListener;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionListener;

import com.netscape.management.client.Framework;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.StatusItemProgress;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.preferences.PreferenceManager;
import com.netscape.management.client.preferences.Preferences;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.ResourceSet;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPUrl;


/**
 * SearchResultPanel is a component used to invoke an LDAP search and display
 * the search results. Its functionality is self contained so it can be
 * embedded easily into other displays. Its features include the ability to
 * invoke the search in a separate thread, to cancel the search, to display
 * the results, and to change the attributes that are displayed for the results.
 *
 * @see VLDirectoryTable
 * @see VLDirectoryTableModel
 */
public class SearchResultPanel extends JPanel {
    private static final String PREFERENCES_RESULT_TABLE = "SearchResultTable";
    public static final String PREFERENCE_COLUMN_COUNT = "ColumnCount";
    public static final String PREFERENCE_COLUMN_ATTRIBUTE_PREFIX = "Attribute";
    public static final String PREFERENCE_COLUMN_LABEL_PREFIX = "Label";

    ResourceSet _resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");
    VLDirectoryTable _resultList;


    /**
    * This version of the constructor does not allow the
    * displayed attributes to be changed.
    *
    * @param parent  the embedding component handles action events
    */
    public SearchResultPanel(ActionListener parent) {
        Hashtable map = new Hashtable();
        Vector header = new Vector();

        PreferenceManager pm = PreferenceManager.getPreferenceManager(
                Framework.IDENTIFIER, Framework.MAJOR_VERSION);
        Preferences p = pm.getPreferences(PREFERENCES_RESULT_TABLE);

        int count = p.getInt(PREFERENCE_COLUMN_COUNT, -1);
        if (count == -1) {
            // There is no valid saved preferences for this user.
            // Get default table columns.
            count = Integer.parseInt(
                    _resource.getString("SearchResultPanel", "ColumnLabelCount"));
            p.set(PREFERENCE_COLUMN_COUNT, count); // Store for future use.
            String labelInfo;
            String attribute;
            String label;
            int commaIndex;
            for (int i = 0; i < count; i++) {
                labelInfo = _resource.getString("SearchResultPanel", "ColumnLabel"+i);
                commaIndex = labelInfo.indexOf(',');
                attribute =
                        labelInfo.substring(0, commaIndex).toLowerCase();
                label = labelInfo.substring(commaIndex + 1);
                p.set(PREFERENCE_COLUMN_ATTRIBUTE_PREFIX + i,
                        attribute); // Store for future use.
                        p.set(
                        PREFERENCE_COLUMN_LABEL_PREFIX + i, label); // Store for future use.
                        map.put(attribute, label);
                header.addElement(attribute);
            }
        } else {
            String attribute;
            String label;
            for (int i = 0; i < count; i++) {
                attribute = p.getString(
                        PREFERENCE_COLUMN_ATTRIBUTE_PREFIX + i);
                label = p.getString(PREFERENCE_COLUMN_LABEL_PREFIX + i);
                if (attribute != null && label != null) {
                    map.put(attribute, label);
                    header.addElement(attribute);
                }
            }
        }

        _resultList = new VLDirectoryTable(map, header, p);
        _resultList.getAccessibleContext().setAccessibleDescription(_resource.getString("SearchResultPanel", "table_tt"));

        setLayout(new BorderLayout());
        add("Center", _resultList);
    }


    /**
     * This version of the constructor does allow the displayed
     * attributes to be changed. It lets the result list dynamically
      * retrieve the attributes for user, group, and ou object classes
      * using the LDAP schema.
     *
     * @param ci      the session information
     * @param parent  the embedding component handles action events
     */
    public SearchResultPanel(ConsoleInfo ci, ActionListener parent) {
        this(parent);
        _resultList.setConsoleInfo(ci);
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
        _resultList.setColumnInfo(columnAttributes, columnDisplayNames);
    }


    /**
      * Gets the maximum number of results that can be retrieved and displayed
      * if using DS 3.x. For DS 4.0 and beyond, virtual list controls obviate
      * the need for this API.
      *
      * @return the maximum number of results allowed
      */
    public int getMaxResults() {
        return _resultList.getMaxResults();
    }


    /**
      * Sets the maximum number of results that can be retrieved and displayed
      * if using DS 3.x. For DS 4.0 and beyond, virtual list controls obviate
      * the need for this API.
      *
      * @param  maxResults  the maximum number of results allowed
      */
    public void setMaxResults(int maxResults) {
        _resultList.setMaxResults(maxResults);
    }


    /**
      * Adds a list listener.
      *
      * @param listener  list listener to add
      */
    public void addListSelectionListener(ListSelectionListener listener) {
        _resultList.addListSelectionListener(listener);
    }


    /**
      * Adds a mouse listener.
      *
      * @param listener  mouse listener to add
      */
    public void addTableMouseListener(MouseListener listener) {
        _resultList.addTableMouseListener(listener);
    }


    /**
      * Handles invoking search using an LDAP URL.
      *
      * @param ldc      the connection to the LDAP server
      * @param ldapURL  the LDAP URL
      */
    public void doSearch(LDAPConnection ldc, LDAPUrl ldapURL) {
        doSearch(ldc, ldapURL.getDN(), ldapURL.getScope(),
                ldapURL.getFilter());
    }


    /**
      * Defaults the search scope to <bold>sub</bold>.
      *
      * @param ldc     the connection to the LDAP server
      * @param baseDN  the base DN to search from
      * @param filter  the search filter
      */
    public void doSearch(LDAPConnection ldc, String baseDN, String filter) {
        doSearch(ldc, baseDN, LDAPConnection.SCOPE_SUB, filter);
    }


    /**
      * Invokes the LDAP search in a separate thread. It displays a progress
      * dialog which can be cancelled to delete the thread and quit the search.
         *
         * @param ldc     the connection to the LDAP server
         * @param baseDN  the base DN to search from
         * @param scope   the search scope
         * @param filter  the search filter
      */
    public void doSearch(LDAPConnection ldc, String baseDN, int scope,
            String filter) {
        Frame f = (Frame) SwingUtilities.getAncestorOfClass(Frame.class,
                this);
                setProgressIndicator(
                        _resource.getString("SearchResultPanel", "CancelSearchLabel"));
                CancelSearchDialog promptDialog = new CancelSearchDialog(f,
                        _resource.getString("SearchResultPanel",
                        "CancelSearchTitle"),
                        _resource.getString("SearchResultPanel", "CancelSearchLabel"));

                SearchThread thread =
                        new SearchThread(_resultList, ldc, baseDN,
                        scope, filter, promptDialog);
                promptDialog.setWorkThread(thread);
                thread.start();

                promptDialog.setVisible(true); // Display search cancel dialog and wait.
        if (promptDialog.isCancel()) {
            _resultList.cancelSearch();
            Debug.println("SearchResultPanel: search cancelled");
        }
        // 335960: Advance search freezes Oxygen console
        //  workaround until better solution is found
        //promptDialog.dispose();
        clearProgressIndicator();
    }


    /**
      * Set progress indicators
      *
      */
    private void setProgressIndicator(String text) {
        Framework f = (Framework) SwingUtilities.getAncestorOfClass(
                Framework.class, this);
                if (f == null)
                    return;
                f.setBusyCursor(true);
                f.changeStatusItemState(Framework.STATUS_TEXT, text);
                f.changeStatusItemState(ResourcePage.STATUS_PROGRESS,
                        StatusItemProgress.STATE_BUSY);
            }

            /**
              * Clear progress indicators
              *
              */
    private void clearProgressIndicator() {
        Framework f = (Framework) SwingUtilities.getAncestorOfClass(
                Framework.class, this);
                if (f == null)
                    return;
                f.setBusyCursor(false);
                f.changeStatusItemState(Framework.STATUS_TEXT, "");
                f.changeStatusItemState(ResourcePage.STATUS_PROGRESS,
                        Integer.valueOf(0));
            }

            /**
              * Returns the number of selected rows.
                 *
                 * @return the number of selected rows
              */
    public int getSelectedRowCount() {
        return _resultList.getSelectedRowCount();
    }


    /**
      * Adds an entry to the results table.
         *
         * @param ldapEntry  the entry to add to the results table
      */
    public void addElement(LDAPEntry ldapEntry) {
        _resultList.addRow(ldapEntry);
    }


    /**
      * Adds a message to the results table.
         *
         * @param message  the message to add to the results table
      */
    public void addElement(String message) {
        _resultList.addRow(message);
    }


    /**
      * Returns the number of items in the results table
         *
         * @return the number of items in the results table
      */
    public int getListCount() {
        return _resultList.getRowCount();
    }


    /**
      * @deprecated  Replaced by removeAllElements()
      * @see  #removeAllElements()
      */
    @Deprecated
    public void removeAllElement() {
        _resultList.deleteAllRows();
    }


    /**
      * Removes all items in the results table.
      */
    public void removeAllElements() {
        _resultList.deleteAllRows();
    }


    /**
      * Deletes the rows for the specified entries.
      *
      * @param entries  the Vector of entries to delete
      */
    public void deleteRows(Vector entries) {
        _resultList.deleteRows(entries);
    }


    /**
      * Returns the selected entry.
      *
      * @return  the selected entry
      */
    public LDAPEntry getSelectedItem() {
        return _resultList.getRow(_resultList.getSelectedRow());
    }

    /**
      * Update selected entry
      *
      * @param ldapEntry  replace current selected entry with this entry
      */
    public void updatedSelectedItem(LDAPEntry ldapEntry) {
        _resultList.replaceRow(ldapEntry, _resultList.getSelectedRow());
    }


    /**
      * Returns all selected entries.
      *
      * @return  the Vector of all selected entries
      */
    public Vector getSelectedEntries() {
        return _resultList.getSelectedEntries();
    }


    /**
      * Returns the row number indicated by the coordinate in the table.
      *
      * @param p  the coordinate in the table
      */
    public int rowAtPoint(Point p) {
        return _resultList.rowAtPoint(p);
    }
}


/**
  * SearchThread handles performing the LDAP search in a separate thread.
  */
class SearchThread extends Thread {
    private VLDirectoryTable _table;
    private LDAPConnection _connection;
    private String _baseDN;
    private int _scope;
    private String _query;
    private CancelSearchDialog _dialog;


    /**
     * Constructor requires all parameters necessary for the search.
     *
     * @param table       the results table
     * @param connection  the connection to the LDAP server
     * @param baseDN      the search base DN
     * @param scope       the scope of the search
     * @param query       the search query string
     * @param dialog      dialog to dismiss when search is completed
     */
    public SearchThread(VLDirectoryTable table,
            LDAPConnection connection, String baseDN, int scope,
            String query, CancelSearchDialog dialog) {
        _table = table;
        _connection = connection;
        _baseDN = baseDN;
        _scope = scope;
        _query = query;
        _dialog = dialog;
    }


    /**
      * Runs the search.
      */
    public void run() {
        try {
            sleep(500); // Give the dialog a chance to display
            _table.doSearch(_connection, _baseDN, _scope, _query);
            _dialog.setVisible(false);
        } catch (InterruptedException e) {
        }
    }
}
