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

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements a duplicate self test exception.
 * EDuplicateSelfTestExceptions are derived from ESelfTestExceptions
 * in order to allow users to easily do self tests without try-catch clauses.
 *
 * EDuplicateSelfTestExceptions should be caught by SelfTestSubsystem managers.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class EDuplicateSelfTestException
        extends ESelfTestException {
    ////////////////////////
    // default parameters //
    ////////////////////////

    ///////////////////////
    // helper parameters //
    ///////////////////////

    /**
     *
     */
    private static final long serialVersionUID = -7484729117186395701L;
    private String mInstanceName = null;
    private String mInstanceStore = null;
    private String mInstanceParameter = null;
    private String mInstanceValue = null;

    ////////////////////////////////////////////
    // EDuplicateSelfTestException parameters //
    ////////////////////////////////////////////

    ///////////////////////////////////////////////
    // ESelfTestException parameters (inherited) //
    ///////////////////////////////////////////////

    /////////////////////
    // default methods //
    /////////////////////

    /**
     * Constructs a "duplicate" self test exception.
     * <P>
     *
     * @param instanceName duplicate "instanceName" exception details
     */
    public EDuplicateSelfTestException(String instanceName) {
        super("The self test plugin property named "
                + instanceName
                + " already exists.");

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        }

        // store passed-in parameters for use by helper methods
        mInstanceName = instanceName;
    }

    /**
     * Constructs a "duplicate" self test exception where the value is always
     * a duplicate from a name/value pair
     * <P>
     *
     * @param instanceName duplicate "instanceName" exception details
     * @param instanceValue duplicate "instanceValue" exception details
     */
    public EDuplicateSelfTestException(String instanceName,
            String instanceValue) {
        super("The self test plugin property named "
                + instanceName
                + " contains a value of "
                + instanceValue
                + " which already exists.");

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        }
        if (instanceValue != null) {
            instanceValue = instanceValue.trim();
        }

        // store passed-in parameters for use by helper methods
        mInstanceName = instanceName;
        mInstanceValue = instanceValue;
    }

    /**
     * Constructs a "duplicate" self test exception where the parameter is a
     * duplicate from a substore.parameter/value pair; (the value passed in may
     * be null).
     * <P>
     *
     * @param instanceStore duplicate "instanceStore" exception details
     * @param instanceParameter duplicate "instanceParameter" exception details
     * @param instanceValue duplicate "instanceValue" exception details
     *            (may be null)
     */
    public EDuplicateSelfTestException(String instanceStore,
            String instanceParameter,
            String instanceValue) {
        super("The self test plugin property named "
                + instanceStore + "." + instanceParameter
                + " is a duplicate.");

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceStore != null) {
            instanceStore = instanceStore.trim();
        }
        if (instanceParameter != null) {
            instanceParameter = instanceParameter.trim();
        }
        if (instanceValue != null) {
            instanceValue = instanceValue.trim();
        }

        // store passed-in parameters for use by helper methods
        mInstanceStore = instanceStore;
        mInstanceParameter = instanceParameter;
        mInstanceValue = instanceValue;
    }

    ////////////////////
    // helper methods //
    ////////////////////

    /**
     * Returns the instance name associated with this self test.
     * <P>
     *
     * @return name portion of the name/value pair
     */
    public String getInstanceName() {
        return mInstanceName;
    }

    /**
     * Returns the store associated with this self test.
     * <P>
     *
     * @return substore portion of the substore.parameter/value pair
     */
    public String getInstanceStore() {
        return mInstanceStore;
    }

    /**
     * Returns the parameter associated with this self test.
     * <P>
     *
     * @return parameter portion of the substore.parameter/value pair
     */
    public String getInstanceParameter() {
        return mInstanceParameter;
    }

    /**
     * Returns the value associated with this self test.
     * <P>
     *
     * @return value portion of the name/value pair
     */
    public String getInstanceValue() {
        return mInstanceValue;
    }

    /////////////////////////////////////////
    // EDuplicateSelfTestException methods //
    /////////////////////////////////////////

    ////////////////////////////////////////////
    // ESelfTestException methods (inherited) //
    ////////////////////////////////////////////

    /* Note that all of the following ESelfTestException methods
     * are inherited from the ESelfTestException class:
     *
     * public ESelfTestException( String msg );
     */
}
