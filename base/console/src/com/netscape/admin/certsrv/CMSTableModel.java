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


import java.util.*;
import javax.swing.table.*;
import com.netscape.management.client.util.*;

/**
 * Generic base class for the JTable data container
 * It provides <B>FORWARD</B> listing of the data.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 * @see javax.swing.table.AbstractTableModel
 */
public class CMSTableModel extends AbstractTableModel {

    /*==========================================================
     * variables
     *==========================================================*/

    //log
    protected static String DATE = "DATE";
    protected static String TIME = "TIME";
    protected static String DETAILS = "DETAILS";
    protected static String SEVERITY = "SEVERITY";
    protected static String SOURCE = "SOURCE";

    //property table
    protected static String ATTRIBUTE = "ATTRIBUTE";
    protected static String VALUE = "VALUE";

    //repository
    protected static String REQUESTNO = "REQUESTNO";
    protected static String REQUESTSTATUS = "REQUESTSTATUS";
    protected static String REQUESTTYPE = "REQUESTTYPE";
    protected static String RECORDNUMBER = "RECORDNUMBER";
    protected static String STATUS = "STATUS";
    protected static String SERIALNO = "SERIALNO";
    protected static String VERSION = "VERSION";
    protected static String SUBJECT = "SUBJECT";
    protected static String SIGNALG = "SIGNALG";
    protected static String NOTBEFORE = "NOTBEFORE";
    protected static String NOTAFTER = "NOTAFTER";
    protected static String NAME = "NAME";
    protected static String DEPARTMENT = "DEPARTMENT";
    protected static String EMAIL = "EMAIL";
    protected static String PHONE = "PHONE";
    protected static String OID = "OID";
    protected static String CLASSNAME = "CLASSNAME";
    protected static String DESC = "DESC";
    protected static String UIMAPPER = "UIMAPPER";
    protected static String USERID = "USERID";
    protected static String FULLNAME = "FULLNAME";
    protected static String CERTIFICATE = "CERTIFICATE";
    protected static String POLICY_IMPL = "POLICY_IMPL";
    protected static String POLICY_TYPE = "POLICY_TYPE";
    protected static String POLICY_RULE = "POLICY_RULE";
    protected static String PROFILE_IMPL = "PROFILE_IMPL";
    protected static String PROFILE_RULE = "PROFILE_RULE";
    protected static String JOBS_IMPL = "JOBS_IMPL";
    protected static String JOBS_RULE = "JOBS_RULE";
    protected static String PUBLISHER_IMPL = "PUBLISHER_IMPL";
    protected static String PUBLISHER_RULE = "PUBLISHER_RULE";
    protected static String MAPPER_IMPL = "MAPPER_IMPL";
    protected static String MAPPER_RULE = "MAPPER_RULE";
    protected static String RULE_IMPL = "RULE_IMPL";
    protected static String RULE_RULE = "RULE_RULE";
    protected static String CRLEXTS_RULE = "CRLEXTS_RULE";
    protected static String OCSPSTORES_RULE = "OCSPSTORES_RULE";
    protected static String LOG_IMPL = "LOG_IMPL";
    protected static String LOG_RULE = "LOG_RULE";
    protected static String PLUGIN = "PLUGIN";
    protected static String RULE = "RULE";
    protected static String CONFIG = "CONFIG";
    protected static String SERVLETNAME = "SERVLETNAME";

    //user and group
    protected static String DEFAULTGROUP = "DEFAULTGROUP";
    protected static String GROUPNAME = "GROUPNAME";
    protected static String GROUPDESC = "GROUPDESC";
    protected static String MEMBER = "MEMBER";

    protected Vector _columnNames = new Vector();     // name container
    protected Vector _tableColumns = new Vector();    // column container
    protected ResourceBundle mResource;               // resource boundle

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSTableModel() {
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
    }


    /*==========================================================
	 * public methods
     *==========================================================*/

    public int getColumnCount() {
        return _columnNames.size();
    }

    public int getRowCount() {
        if (getColumnCount() > 0 ) {
            Vector v = (Vector)_tableColumns.elementAt(0);
            return v.size();
        }
        return 0;
    }

    public String getColumnName(int column) {
        if (column >= _columnNames.size())
            return "";
        return (String)_columnNames.elementAt(column);
    }

    public boolean isCellEditable(int row, int col) {
        return false;
    }

    public synchronized void setValueAt(Object aValue, int row, int column) {
            Vector col = (Vector)_tableColumns.elementAt(column);
            col.setElementAt(aValue, row);
    }

    public synchronized Object getValueAt(int row, int col) {
        if ( getColumnCount() > 0 ) {
            Vector v = (Vector)_tableColumns.elementAt(col);
            return v.elementAt(row);
        }
        return null;
    }

    public synchronized void removeAllRows() {
        for (int i=0; i<_tableColumns.size(); i++) {
            Vector v = (Vector)_tableColumns.elementAt(i);
            v.removeAllElements();
        }
        fireTableDataChanged();
    }

    /**
     * add specified data to the end of the table
     */
    public synchronized void addRow(Vector values) {
        for (int i=0; i < values.size(); i++) {
            Vector v = (Vector)_tableColumns.elementAt(i);
            v.addElement(values.elementAt(i));
        }
        fireTableDataChanged();
    }

    /**
     * remove specified row at index position
     */
    public void removeRow(int index)
        throws ArrayIndexOutOfBoundsException
    {
        for (int i=0; i < _tableColumns.size(); i++) {
            Vector v = (Vector)_tableColumns.elementAt(i);
            v.removeElementAt(index);
        }
        fireTableDataChanged();
    }

    public synchronized void addColumn(String name) {
        _columnNames.addElement(name);
        _tableColumns.addElement(new Vector());
    }

    public Class getColumnClass(int c) {
        return getValueAt(0, c).getClass();
    }

    /**
      * Returns detail information for a given cell.  If the Object
	  * is a Component, it is set in the detail pane, otherwise the
	  * toString() value of object is displayed as text.
	  * Called by LogViewer
      */
	public Object getDetailInfo(int column, int row) {
		return null;
	}

    /**
      * Returns a boolean value indicating whether any log data
	  * has detail information.
	  * Called by LogViewer
      */
	public boolean hasDetailInfo() {
		return false;
	}

    /**
      * Returns a component that displays a log filter.
	  * Called by LogViewer
      *
	public IFilterComponent getFilterComponent(Object viewInstance) {
		return (IFilterComponent)null;
	}
	*/

    /**
      * Sets an object representing a log filter.   This object
	  * is obtained from the IFilterComponent.
	  * Called by LogViewer
      */
	public void setFilter(Object viewInstance, Object filter) {
	}

    /**
      * Notification that the log should be updated.
	  * Called by LogViewer
      */
	public void updateNow(Object viewInstance) {
	}

    /*==========================================================
	 * protected methods
     *==========================================================*/

    /**
     * Initialize the column headings
     */
    protected void init(String[] column ) {
		for( int i = 0; i < column.length; i++ ) {
		    String name;
		    try {
			    name = mResource.getString("LOG_COLUMN_"+column[i]+"_LABEL");
			} catch (MissingResourceException e) {
			    name = "Missing Label";
			}
			//Debug.println("LogDataModel: init() - add Column: "+name);
			addColumn( name );
		}
	}
}
