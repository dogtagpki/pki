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
package com.netscape.admin.certsrv.status;

import java.text.ParseException;
import java.util.Vector;

import com.netscape.admin.certsrv.CMSTableModel;
import com.netscape.admin.certsrv.IDataProcessor;

/**
 * LogDataModel to be displayed at the right hand side
 *
 * We need the log order in REVERSE.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.status
 */
public class LogDataModel extends CMSTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    public static String ILOGENTRY = "ILOGENTRY";

    protected String[] mColumns = {SOURCE, SEVERITY, DATE, TIME, DETAILS};
    protected ILogParser mParser = null;

    /*==========================================================
     * constructors
     *==========================================================*/
     public LogDataModel() {
        super();
        init(mColumns);
     }

     public LogDataModel(ILogParser parser) {
        this();
        mParser = parser;
     }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * set the log parser
     */
    public void setParser(ILogParser parser) {
        mParser = parser;
    }


    /**
     * Process data called back
     */
    @Override
    public void processData(Object data) {
        Vector<Object> row;
        if (mParser == null)
            mParser = new DefaultLogParser();
        try {
            row = mParser.parse(data);
        } catch (ParseException e) {
            //Debug.println("LogDataModel: processData()");
            return;
        }
        addRow(row);
    }

    /**
     * NEED TO OVERWRITE THE TABLE MODEL ADD FUNCTION
     * SINCE WE ARE PROVIDING REVERSE ORDER ENTRIES IN
     * LOG FILES
     */
    @Override
    public synchronized void addRow(Vector<Object> values) {
        int row = 0;
        for (int i=0; i < values.size(); i++) {
            Vector<Object> v = _tableColumns.elementAt(i);
            v.insertElementAt(values.elementAt(i),0);
            if (i == 0)
                row = v.size() - 1;
        }
        fireTableDataChanged();
    }

}
