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

import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;


/**
 * instance Data model - represents the instance
 * table information
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
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
    protected Vector mRules;

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSRuleDataModel() {
        super();
		mColumns = getColumns();
        init(mColumns);
        mRules = new Vector();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

	protected abstract String[] getColumns();
	
    /**
     * clean up the table including the datat objects
     */
    public void removeAllRows() {
        super.removeAllRows();
        mRules.removeAllElements();
    }    
    
    
    public Vector getRules() {
        return (Vector) mRules.clone();    
    }
    
    public boolean isCellEditable(int row, int col) {
        return false;
    }
    
}
