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

import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;

/**
 * WizardInfo for reconfiguring the Recovery MN Scheme
 * Once complete, we need to zap this object.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class MNSchemeWizardInfo extends WizardInfo {

    /*==========================================================
     * variables
     *==========================================================*/
    private AdminConnection mConnection;
    private int mM, mN;

	/*==========================================================
     * constructors
     *==========================================================*/
    public MNSchemeWizardInfo(AdminConnection conn, int m, int n) {
        super();
        mConnection = conn;
        mM = m;
        mN = n;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    //get m
    public String getM() {
        return Integer.toString(mM);
    }

    //get n
    public String getN() {
        return Integer.toString(mN);
    }

    public String getNewM() {
        if(containsKey(Constants.PR_RECOVERY_M))
            return (String) get(Constants.PR_RECOVERY_M);
        return getM();
    }

    public String getNewN() {
        if(containsKey(Constants.PR_RECOVERY_N))
            return (String) get(Constants.PR_RECOVERY_N);
        return getN();
    }


    //add information into info
    public void add(String name, String value) {
        put(name,value);
    }

    /**
     * Clean up the data struture stored within this container
     */
    public void cleanup() {
        clear();
    }

    /**
     * Perform Operation
     */
    public void changeScheme() throws EAdminException {

        NameValuePairs param = new NameValuePairs();
        param.put(Constants.PR_RECOVERY_M, (String) get(Constants.PR_RECOVERY_M));
        param.put(Constants.PR_RECOVERY_N, (String) get(Constants.PR_RECOVERY_N));
        param.put(Constants.PR_RECOVERY_AGENT, (String) get(Constants.PR_RECOVERY_AGENT));
        param.put(Constants.PR_OLD_RECOVERY_AGENT, (String) get(Constants.PR_OLD_RECOVERY_AGENT));

        mConnection.modify(DestDef.DEST_KRA_ADMIN,
                               ScopeDef.SC_MNSCHEME,
                               Constants.RS_ID_CONFIG,
                               param);

        //param.clear();
    }
}
