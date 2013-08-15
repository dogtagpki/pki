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
import java.util.Enumeration;
import java.util.Vector;

/**
 * A collection of AgentApproval objects.
 * <single-threaded>
 *
 * @version $Revision$, $Date$
 */
public class AgentApprovals
        implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -3827259076159153561L;

    /**
     * Adds an approval to approval's list.
     * <p>
     * If an approval is already present for this user, it is updated with a new date. Otherwise a new value is
     * inserted.
     *
     * @param userName user name of the approving agent
     */
    public AgentApproval addApproval(String userName) {
        AgentApproval a = findApproval(userName);

        // update existing approval
        if (a != null) {
            a.mDate = new Date(); /* CMS.getCurrentDate(); */
            return a;
        }

        a = new AgentApproval(userName);
        mVector.addElement(a);
        return a;
    }

    /**
     * Removes an approval from approval's list.
     * <p>
     * If there is no approval for this userName, this call does nothing.
     *
     * @param userName user name of the approving agent
     */
    public void removeApproval(String userName) {
        AgentApproval a = findApproval(userName);

        if (a != null)
            mVector.removeElement(a);
    }

    /**
     * Finds an existing AgentApproval for the named user.
     *
     * @param userName user name of the approving agent
     * @return an AgentApproval object
     */
    public AgentApproval findApproval(String userName) {
        AgentApproval a = null;

        // search
        for (int i = 0; i < mVector.size(); i++) {
            a = mVector.elementAt(i);

            if (a.mUserName.equals(userName))
                break;
        }

        return a;
    }

    /**
     * Returns an enumeration of the agent approvals
     *
     * @return an enumeration of the agent approvals
     */
    public Enumeration<AgentApproval> elements() {
        return mVector.elements();
    }

    /**
     * Returns the AgentApprovals as a Vector of strings.
     * Each entry in the vector is of the format:
     * epoch;username
     * where epoch is the date.getTime()
     * <p>
     * This is used for serialization in Request.setExtData().
     *
     * @return The string vector.
     */
    public Vector<String> toStringVector() {
        Vector<String> retval = new Vector<String>(mVector.size());
        for (int i = 0; i < mVector.size(); i++) {
            AgentApproval a = mVector.elementAt(i);
            retval.add(a.getDate().getTime() + ";" + a.getUserName());
        }

        return retval;
    }

    /**
     * Recreates an AgentApprovals instance from a Vector of strings that
     * was created by toStringVector().
     *
     * @param stringVector The vector of strings to translate
     * @return the AgentApprovals instance or null if it can't be translated.
     */
    public static AgentApprovals fromStringVector(Vector<String> stringVector) {
        if (stringVector == null) {
            return null;
        }
        AgentApprovals approvals = new AgentApprovals();
        for (int i = 0; i < stringVector.size(); i++) {
            try {
                String approvalString = stringVector.get(i);
                String[] parts = approvalString.split(";", 2);
                if (parts.length != 2) {
                    return null;
                }
                Long epoch = new Long(parts[0]);
                Date date = new Date(epoch.longValue());

                AgentApproval approval = new AgentApproval(parts[1]);
                approval.mDate = date;

                approvals.mVector.add(approval);
            } catch (ClassCastException e) {
                return null;
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return approvals;
    }

    public int size() {
        return mVector.size();
    }

    public AgentApproval get(int i) {
        return mVector.get(i);
    }

    protected Vector<AgentApproval> mVector = new Vector<AgentApproval>();
}
