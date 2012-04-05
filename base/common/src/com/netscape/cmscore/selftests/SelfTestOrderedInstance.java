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
// package statement //
///////////////////////

package com.netscape.cmscore.selftests;

///////////////////////
// import statements //
///////////////////////

import java.util.StringTokenizer;

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements a single element in
 * an ordered list of self test instances.
 * <P>
 *
 * @author mharmsen
 * @author thomask
 * @version $Revision$, $Date$
 */
public class SelfTestOrderedInstance {
    ////////////////////////
    // default parameters //
    ////////////////////////

    private static final String ELEMENT_DELIMITER = ":";
    private static final String CRITICAL = "critical";

    ////////////////////////////////////////
    // SelfTestOrderedInstance parameters //
    ////////////////////////////////////////

    private String mInstanceName = null;
    private boolean mCritical = false;

    /////////////////////
    // default methods //
    /////////////////////

    /**
     * Constructs a single element within an ordered list of self tests.
     * A "listElement" contains a string of the form "[instanceName]" or
     * "[instanceName]:critical".
     * <P>
     *
     * @param listElement a string containing the "instanceName" and
     *            information indictating whether or not the instance is "critical"
     */
    public SelfTestOrderedInstance(String listElement) {
        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (listElement != null) {
            listElement = listElement.trim();
        } else {
            // no listElement is present
            return;
        }

        StringTokenizer token = new StringTokenizer(listElement,
                ELEMENT_DELIMITER);

        // extract the mInstanceName
        if (token.hasMoreTokens()) {
            // prior to the ELEMENT_DELIMITER
            mInstanceName = token.nextToken().trim();

            // extract the mCritical indicator
            if (token.hasMoreTokens()) {
                // something exists after the ELEMENT_DELIMITER
                if (token.nextToken().trim().equals(CRITICAL)) {
                    mCritical = true;
                }
            }
        } else {
            // no ELEMENT_DELIMITER is present
            mInstanceName = listElement;
        }

    }

    /////////////////////////////////////
    // SelfTestOrderedInstance methods //
    /////////////////////////////////////

    /**
     * Returns the name associated with this self test; may be null.
     * <P>
     *
     * @return instanceName of this self test
     */
    public String getSelfTestName() {
        return mInstanceName;
    }

    /**
     * Returns the criticality associated with this self test.
     * <P>
     *
     * @return true if failure of this self test is fatal when
     *         it is executed; otherwise return false
     */
    public boolean isSelfTestCritical() {
        return mCritical;
    }

    /**
     * Sets/resets the criticality associated with this self test.
     * <P>
     *
     * @param criticalMode the criticality of this self test
     */
    public void setSelfTestCriticalMode(boolean criticalMode) {
        mCritical = criticalMode;
    }
}
