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
package com.netscape.certsrv.request;

import java.io.Serializable;
import java.util.Date;

/**
 * The AgentApproval class contains the record of a
 * single agent approval.
 *
 * @version $Revision$, $Date$
 */
public class AgentApproval
        implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -3444654917454805225L;

    /**
     * Returns the approving agent's user name.
     *
     * @return an identifier for the agent
     */
    public String getUserName() {
        return mUserName;
    }

    /**
     * Returns the date of the approval
     *
     * @return date and time of the approval
     */
    public Date getDate() {
        return mDate;
    }

    /**
     * AgentApproval class constructor
     *
     * @param userName user name of the approving agent
     */
    AgentApproval(String userName) {
        mUserName = userName;
    }

    String mUserName;
    Date mDate = new Date(); /* CMS.getCurrentDate(); */
}
