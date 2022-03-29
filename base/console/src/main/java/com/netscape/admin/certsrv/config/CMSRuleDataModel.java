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
package com.netscape.admin.certsrv.config;

import java.util.Vector;

import com.netscape.admin.certsrv.CMSContentTableModel;
import com.netscape.admin.certsrv.IDataProcessor;


/**
 * instance Data model - represents the instance
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public abstract class CMSRuleDataModel extends CMSContentTableModel
    implements IDataProcessor
{

    /*==========================================================
     * variables
     *==========================================================*/
    public static final String RULE_NAME = "RULENAME";
    public static final String RULE_STAT = "STATUS";
	public static final String RULE_IMPL = "IMPL";
	public static final String RULE_TYPE = "TYPE";

    protected static String[] mColumns = null;
    protected Vector<String> mRules;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSRuleDataModel() {
        super();
		mColumns = getColumns();
        init(mColumns);
        mRules = new Vector<>();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

	protected abstract String[] getColumns();

    /**
     * clean up the table including the datat objects
     */
    @Override
    public void removeAllRows() {
        super.removeAllRows();
        mRules.removeAllElements();
    }


    public Vector<String> getRules() {
        return (Vector<String>) mRules.clone();
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

}
