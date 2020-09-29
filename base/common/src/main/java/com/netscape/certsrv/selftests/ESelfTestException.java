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

package com.netscape.certsrv.selftests;

///////////////////////
// import statements //
///////////////////////

import com.netscape.certsrv.base.EBaseException;

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements a self test exception. ESelfTestExceptions
 * are derived from EBaseExceptions in order to allow users
 * to easily do self tests without try-catch clauses.
 *
 * ESelfTestExceptions should be caught by SelfTestSubsystem managers.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class ESelfTestException
        extends EBaseException {
    ////////////////////////
    // default parameters //
    ////////////////////////

    ///////////////////////////////////
    // ESelfTestException parameters //
    ///////////////////////////////////

    /**
     *
     */
    private static final long serialVersionUID = -8001373369705595891L;
    private static final String SELFTEST_RESOURCES = SelfTestResources.class.getName();

    ///////////////////////////////////////////
    // EBaseException parameters (inherited) //
    ///////////////////////////////////////////

    /* Note that all of the following EBaseException parameters
     * are inherited from the EBaseException class:
     *
     * public Object mParams[];
     */

    /////////////////////
    // default methods //
    /////////////////////

    /**
     * Constructs a self test exception.
     * <P>
     *
     * @param msg exception details
     */
    public ESelfTestException(String msg) {
        super(msg);
    }

    public ESelfTestException(String msg, Throwable cause) {
        super(msg, cause);
    }

    ////////////////////////////////
    // ESelfTestException methods //
    ////////////////////////////////

    /**
     * Returns the bundle file name.
     * <P>
     *
     * @return name of bundle class associated with this exception.
     */
    protected String getBundleName() {
        return SELFTEST_RESOURCES;
    }

    ////////////////////////////////////////
    // EBaseException methods (inherited) //
    ////////////////////////////////////////

    /* Note that all of the following EBaseException methods
     * are inherited from the EBaseException class:
     *
     * public EBaseException( String msgFormat );
     *
     * public EBaseException( String msgFormat, String param );
     *
     * public EBaseException( String msgFormat, Exception param );
     *
     * public EBaseException( String msgFormat, Object params[] );
     *
     * public Object[] getParameters();
     *
     * public String toString();
     *
     * public String toString( Locale locale );
     */
}
