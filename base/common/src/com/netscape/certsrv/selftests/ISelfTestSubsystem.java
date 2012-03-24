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

import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogEventListener;

//////////////////////
// class definition //
//////////////////////

/**
 * This class defines the interface of a container for self tests.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface ISelfTestSubsystem
        extends ISubsystem {
    ////////////////////////
    // default parameters //
    ////////////////////////

    //////////////////////////////////
    // ISelfTestSubsystem constants //
    //////////////////////////////////

    public static final String ID = "selftests";
    public static final String PROP_CONTAINER = "container";
    public static final String PROP_INSTANCE = "instance";
    public static final String PROP_LOGGER = "logger";
    public static final String PROP_LOGGER_CLASS = "class";
    public static final String PROP_ORDER = "order";
    public static final String PROP_ON_DEMAND = "onDemand";
    public static final String PROP_STARTUP = "startup";

    ///////////////////////////////////////
    // ISubsystem parameters (inherited) //
    ///////////////////////////////////////

    /////////////////////
    // default methods //
    /////////////////////

    ////////////////////////////////
    // ISelfTestSubsystem methods //
    ////////////////////////////////

    //
    // methods associated with the list of on demand self tests
    //

    /**
     * List the instance names of all the self tests enabled to run on demand
     * (in execution order); may return null.
     * <P>
     * 
     * @return list of self test instance names run on demand
     */
    public String[] listSelfTestsEnabledOnDemand();

    /**
     * Enable the specified self test to be executed on demand.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @param isCritical isCritical is either a critical failure (true) or
     *            a non-critical failure (false)
     * @exception EInvalidSelfTestException subsystem has invalid name/value
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    //  public void enableSelfTestOnDemand( String instanceName,
    //                                      boolean isCritical )
    //  throws EInvalidSelfTestException, EMissingSelfTestException;

    /**
     * Disable the specified self test from being able to be executed on demand.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    //  public void disableSelfTestOnDemand( String instanceName )
    //  throws EMissingSelfTestException;

    /**
     * Determine if the specified self test is enabled to be executed on demand.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @return true if the specified self test is enabled on demand
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public boolean isSelfTestEnabledOnDemand(String instanceName)
            throws EMissingSelfTestException;

    /**
     * Determine if failure of the specified self test is fatal when
     * it is executed on demand.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @return true if failure of the specified self test is fatal when
     *         it is executed on demand
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public boolean isSelfTestCriticalOnDemand(String instanceName)
            throws EMissingSelfTestException;

    /**
     * Execute all self tests specified to be run on demand.
     * <P>
     * 
     * @exception EMissingSelfTestException subsystem has missing name
     * @exception ESelfTestException self test exception
     */
    public void runSelfTestsOnDemand()
            throws EMissingSelfTestException, ESelfTestException;

    //
    // methods associated with the list of startup self tests
    //

    /**
     * List the instance names of all the self tests enabled to run
     * at server startup (in execution order); may return null.
     * <P>
     * 
     * @return list of self test instance names run at server startup
     */
    public String[] listSelfTestsEnabledAtStartup();

    /**
     * Enable the specified self test at server startup.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @param isCritical isCritical is either a critical failure (true) or
     *            a non-critical failure (false)
     * @exception EInvalidSelfTestException subsystem has invalid name/value
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    //  public void enableSelfTestAtStartup( String instanceName,
    //                                       boolean isCritical )
    //  throws EInvalidSelfTestException, EMissingSelfTestException;

    /**
     * Disable the specified self test at server startup.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    //  public void disableSelfTestAtStartup( String instanceName )
    //  throws EMissingSelfTestException;

    /**
     * Determine if the specified self test is executed automatically
     * at server startup.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @return true if the specified self test is executed at server startup
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public boolean isSelfTestEnabledAtStartup(String instanceName)
            throws EMissingSelfTestException;

    /**
     * Determine if failure of the specified self test is fatal to
     * server startup.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @return true if failure of the specified self test is fatal to
     *         server startup
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public boolean isSelfTestCriticalAtStartup(String instanceName)
            throws EMissingSelfTestException;

    /**
     * Execute all self tests specified to be run at server startup.
     * <P>
     * 
     * @exception EMissingSelfTestException subsystem has missing name
     * @exception ESelfTestException self test exception
     */
    public void runSelfTestsAtStartup()
            throws EMissingSelfTestException, ESelfTestException;

    //
    // methods associated with the list of self test instances
    //

    /**
     * Retrieve an individual self test from the instances list
     * given its instance name.
     * <P>
     * 
     * @param instanceName instance name of self test
     * @return individual self test
     */
    public ISelfTest getSelfTest(String instanceName);

    //
    // methods associated with multiple self test lists
    //

    /**
     * Returns the ILogEventListener of this subsystem.
     * This method may return null.
     * <P>
     * 
     * @return ILogEventListener of this subsystem
     */
    public ILogEventListener getSelfTestLogger();

    /**
     * This method represents the log interface for the self test subsystem.
     * <P>
     * 
     * @param logger log event listener
     * @param msg self test log message
     */
    public void log(ILogEventListener logger, String msg);

    /**
     * Register an individual self test on the instances list AND
     * on the "on demand" list (note that the specified self test
     * will be appended to the end of each list).
     * <P>
     * 
     * @param instanceName instance name of self test
     * @param isCritical isCritical is either a critical failure (true) or
     *            a non-critical failure (false)
     * @param instance individual self test
     * @exception EDuplicateSelfTestException subsystem has duplicate name
     * @exception EInvalidSelfTestException subsystem has invalid name/value
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    //  public void registerSelfTestOnDemand( String instanceName,
    //                                        boolean isCritical,
    //                                        ISelfTest instance )
    //  throws EDuplicateSelfTestException,
    //         EInvalidSelfTestException,
    //         EMissingSelfTestException;

    /**
     * Deregister an individual self test on the instances list AND
     * on the "on demand" list (note that the specified self test
     * will be removed from each list).
     * <P>
     * 
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    //  public void deregisterSelfTestOnDemand( String instanceName )
    //  throws EMissingSelfTestException;

    /**
     * Register an individual self test on the instances list AND
     * on the "startup" list (note that the specified self test
     * will be appended to the end of each list).
     * <P>
     * 
     * @param instanceName instance name of self test
     * @param isCritical isCritical is either a critical failure (true) or
     *            a non-critical failure (false)
     * @param instance individual self test
     * @exception EDuplicateSelfTestException subsystem has duplicate name
     * @exception EInvalidSelfTestException subsystem has invalid name/value
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    //  public void registerSelfTestAtStartup( String instanceName,
    //                                         boolean isCritical,
    //                                         ISelfTest instance )
    //  throws EDuplicateSelfTestException,
    //         EInvalidSelfTestException,
    //         EMissingSelfTestException;

    /**
     * Deregister an individual self test on the instances list AND
     * on the "startup" list (note that the specified self test
     * will be removed from each list).
     * <P>
     * 
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    //  public void deregisterSelfTestAtStartup( String instanceName )
    //  throws EMissingSelfTestException;

    ////////////////////////////////////
    // ISubsystem methods (inherited) //
    ////////////////////////////////////

    /* Note that all of the following ISubsystem methods
     * are inherited from the ISubsystem class:
     *
     *    public String getId();
     *
     *    public void setId( String id )
     *    throws EBaseException;
     *
     *    public void init( ISubsystem owner, IConfigStore config )
     *    throws EBaseException;
     *
     *    public void startup()
     *    throws EBaseException;
     *
     *    public void shutdown();
     *
     *    public IConfigStore getConfigStore();
     */
}
