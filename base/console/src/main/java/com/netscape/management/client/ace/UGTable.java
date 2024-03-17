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
package com.netscape.management.client.ace;

import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import netscape.ldap.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.ug.*;


/**
 * UGTable is a wrapper over the actual search results table.
 *
 * @see SearchResultPanel
 * @see UGTableModel
 * 
 * @author Andy Hakim
 * @author Peter Lee
 */
class UGTable extends Table 
{
    private ResourceSet resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");

    private UGTableModel dataModel;

    private JPopupMenu tableHeaderMenu;
    private JMenuItem customizeMenuItem;

    private Hashtable map;
    private Vector attributes;
    private Vector columnNames;

    private ConsoleInfo consoleInfo;
    private static String[]availableAttributes;
    private String baseDN;
    private int searchScope = LDAPConnection.SCOPE_SUB;

    /**
      * Constructor
      *
      * @param attrMapping    Mapper that map attribute to a display string
      * @param headerAttr     Attributes that specify how column should be constructed.
      *                        This also determain which attribute should be displayed.
      */
    public UGTable() 
    {
        consoleInfo = null;
        map = new Hashtable(); // TODO: name to attribute mapper
		Vector attrs = new Vector();
		attrs.addElement("cn");
		attrs.addElement("uid");
		attrs.addElement("mail");
		//attrs.addElement("telephoneNumber");
		
		Vector names = new Vector();

		names.addElement(getDisplayFromDescDisplayPair(resource.getString("SearchResultPanel", "ColumnLabel0")));
        names.addElement(getDisplayFromDescDisplayPair(resource.getString("SearchResultPanel", "ColumnLabel1")));
		names.addElement(getDisplayFromDescDisplayPair(resource.getString("SearchResultPanel", "ColumnLabel2")));
        // names.addElement(getDisplayFromDescDisplayPair(resource.getString("SearchResultPanel", "ColumnLabel3")));
		
        dataModel = new UGTableModel(attrs, names);
        setModel(dataModel);
		setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        TableColumnModel tcm = getColumnModel();
        tcm.getColumn(0).setWidth(200);
        tcm.getColumn(1).setWidth(100);
        //tcm.getColumn(2).setPreferredWidth(100);
    }


    /**
      * Changes the number of result table columns, its corresponding
      * attributes, and its display names.
      *
      * @param  columnAttributes    the attributes displayed in the columns
      * @param  columnDisplayNames  the column header names
      */
    public void setColumnInfo(Vector columnAttributes, Vector columnDisplayNames) 
    {
        if (columnAttributes != null && columnDisplayNames != null) 
        {
            int attrSize = columnAttributes.size();
            int labelSize = columnDisplayNames.size();
            if (attrSize == 0 || attrSize != labelSize) 
            {
                Debug.println("VLDirectoryTable.setColumnInfo: invalid parameters: size of column attributes and labels differ");
                return;
            }
            attributes = columnAttributes;
            columnNames = columnDisplayNames;
            dataModel.setColumnInfo(columnAttributes, columnDisplayNames);
        }
        else 
        {
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
    public int getMaxResults() 
    {
        return dataModel.getMaxResults();
    }


    /**
      * Sets the maximum number of results that can be retrieved and displayed
      * if using DS 3.x. For DS 4.0 and beyond, virtual list controls obviate
      * the need for this API.
      *
      * @param  maxResults  the maximum number of results allowed
      */
    public void setMaxResults(int maxResults) 
    {
        dataModel.setMaxResults(maxResults);
    }

    /**
      */
    public void setUserDN(String newBaseDN) 
    {
        baseDN = newBaseDN;
    }

    /**
      */
    public String getUserDN() 
    {
        return baseDN;
    }
    
    /**
      */
    public void setSearchScope(int newSearchScope) 
    {
        searchScope = newSearchScope;
    }

    /**
      */
    public int getSearchScope() 
    {
        return searchScope;
    }

    /**
      * Invokes the LDAP search.
      *
      * @param filter  the search filter
      */
    public synchronized void doSearch(LDAPConnection ldc, String baseDN, String filter)
    {
        dataModel.setPageSize(15);
        dataModel.doSearch(ldc, baseDN, searchScope, filter);
        if (dataModel.getRowCount() > 0) 
        {
            setRowSelectionInterval(0, 0); // Select the first item.
        }
    }


    /**
      * Add a row to the current table.
      *
      * @param ldapEntry  the entry to add
      */
    public void addRow(LDAPEntry ldapEntry) {
        dataModel.addRow(ldapEntry);
    }


    /**
      * Add a message row to the current table.
      *
      * @param String  the message to add
      */
    public void addRow(String message) 
    {
        dataModel.addRow(message);
    }

    /**
      * Replace entry in row with LDAPEntry specified.
      *
      * @param row    row to be replaced
      * @param entry  replace with this entry
      */
    public void replaceRow(LDAPEntry entry, int row) 
    {
        dataModel.replaceRow(entry, row);
    }

    /**
      * Retrieves all selected entries.
      *
      * @return  the vector containing all the selected entries.
      */
    public Vector getSelectedEntries() {
        int index[] = getSelectedRows();
        Vector ldapEntries = new Vector();

        // This supports the case where a message such as "Nothing found"
        // was added to the list AFTER a search.
        if (index.length == 1) 
        {
            if (getRow(index[0]) == null) 
            {
                return ldapEntries;
            }
        }

        for (int i = 0; i < index.length; i++) 
        {
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
    public LDAPEntry getRow(int index) 
    {
        return dataModel.getRow(index);
    }

    /**
      * Retrieves the number of rows in the table.
      *
      * @return  the number of rows in the table.
      */
    public int getRowCount() 
    {
		int rowCount = 0;
		if(dataModel != null)
			rowCount = dataModel.getRowCount();
		else
			rowCount = super.getRowCount();
		return rowCount;
    }

    /**
      * Deletes all rows from this table.
      */
    public void deleteAllRows() 
    {
        dataModel.deleteAllRows();
    }

    /**
      * Deletes specified row.
      * 
      * @param index row to delete
      */
    public void deleteRow(int index) 
    {
		if(index != -1)
		{
			dataModel.deleteRow(index);
		}
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
            dataModel.deleteRow((LDAPEntry)(tmp.elementAt(i)));
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
            dataModel.deleteRow((LDAPEntry)(entries.elementAt(i)));
        }
    }

    /**
      * This calls the clean up method in the data model if the search has
      * been cancelled.
      */
    public void cancelSearch() {
        dataModel.cancelSearch();
    }


    /**
     * Initializes the availableAttributes static member when the user
      * opts to customize the table columns for the first time.
     *
     * @return  true if initialize succeeded; false otherwise
     */
    private boolean initializeAvailableAttributes() {
        if (consoleInfo == null) {
            Debug.println("VLDirectoryTable: no session info to get schema from");
            return false;
        }

        LDAPSchema schema = null;
        LDAPConnection ldc = consoleInfo.getUserLDAPConnection();
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

        if (userObjectClasses == null || groupObjectClasses == null) {
            Debug.println("VLDirectoryTable: cannot get attributes since one or more objectclasses are null");
            return false;
        }

        getAllAttributesFor(allAttributes, userObjectClasses, schema);
        getAllAttributesFor(allAttributes, groupObjectClasses, schema);

        String[] allAttrStrings = new String[allAttributes.size()];
        allAttributes.copyInto(allAttrStrings);

        availableAttributes = allAttrStrings;
        return true;
    }


    /**
      * Dynamically retrieves the attributes for user and group
      * object classes using the LDAP schema.
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
                attr = (Object) enumReq.nextElement();
                if (((String) attr).indexOf("binary") != -1) {
                    continue; // skip binaries
                }
                if (result.indexOf(attr) == -1) {
                    result.addElement(attr); // Only add the attribute if not already present
                }
            }
            while (enumAllow.hasMoreElements()) {
                attr = (Object) enumAllow.nextElement();
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
     * @return <code>String</code> that is <substring2> of <substring1>,<substring2>
     *         or the entire substring if there is no comma seperator
     */
    private String getDisplayFromDescDisplayPair(String descDisplayPair) {
        String display = descDisplayPair;
        int commaPos = descDisplayPair.indexOf(',');
        if (commaPos != -1) {
            display = descDisplayPair.substring(commaPos + 1);
        }
        return display;
    }
}
