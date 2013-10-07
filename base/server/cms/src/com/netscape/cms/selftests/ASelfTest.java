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

package com.netscape.cms.selftests;

///////////////////////
// import statements //
///////////////////////

import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.selftests.EDuplicateSelfTestException;
import com.netscape.certsrv.selftests.EInvalidSelfTestException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.certsrv.selftests.ISelfTest;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements an individual self test.
 * <P>
 *
 * @author mharmsen
 * @author thomask
 * @version $Revision$, $Date$
 */
public abstract class ASelfTest
        implements ISelfTest {
    ////////////////////////
    // default parameters //
    ////////////////////////

    //////////////////////////
    // ISelfTest parameters //
    //////////////////////////

    // parameter information
    private static final String SELF_TEST_NAME = "ASelfTest";

    // variables associated with this specific object
    protected ISelfTestSubsystem mSelfTestSubsystem = null;
    protected String mInstanceName = null;
    protected IConfigStore mConfig = null;
    protected String mPrefix = null;

    /////////////////////
    // default methods //
    /////////////////////

    ///////////////////////
    // ISelfTest methods //
    ///////////////////////

    /**
     * Initializes this subsystem with the configuration store
     * associated with this instance name.
     * <P>
     *
     * @param subsystem the associated subsystem
     * @param instanceName the name of this self test instance
     * @param parameters configuration store (self test parameters)
     * @exception EDuplicateSelfTestException subsystem has duplicate name/value
     * @exception EInvalidSelfTestException subsystem has invalid name/value
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    public void initSelfTest(ISelfTestSubsystem subsystem,
            String instanceName,
            IConfigStore parameters)
            throws EDuplicateSelfTestException,
            EInvalidSelfTestException,
            EMissingSelfTestException {
        // store individual self test class values for this instance
        mSelfTestSubsystem = subsystem;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        } else {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                    CMS.getLogMessage(
                            "SELFTESTS_PARAMETER_WAS_NULL",
                            SELF_TEST_NAME));

            throw new EMissingSelfTestException();
        }

        // store additional individual self test class values for this instance
        mInstanceName = instanceName;

        // compose self test plugin parameter property prefix
        String pluginPath = PROP_PLUGIN + "." + instanceName;

        mConfig = parameters.getSubStore(pluginPath);

        if ((mConfig != null) &&
                (mConfig.getName() != null) &&
                (mConfig.getName() != "")) {
            mPrefix = mConfig.getName().trim();
        } else {
            mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                    CMS.getLogMessage(
                            "SELFTESTS_PARAMETER_WAS_NULL",
                            SELF_TEST_NAME));

            throw new EMissingSelfTestException();
        }

        return;
    }

    /**
     * Notifies this subsystem if it is in execution mode.
     * <P>
     *
     * @exception ESelfTestException failed to start
     */
    public abstract void startupSelfTest()
            throws ESelfTestException;

    /**
     * Stops this subsystem. The subsystem may call shutdownSelfTest
     * anytime after initialization.
     * <P>
     */
    public abstract void shutdownSelfTest();

    /**
     * Returns the name associated with this self test. This method may
     * return null if the self test has not been intialized.
     * <P>
     *
     * @return instanceName of this self test
     */
    public String getSelfTestName() {
        return mInstanceName;
    }

    /**
     * Returns the root configuration storage (self test parameters)
     * associated with this subsystem.
     * <P>
     *
     * @return configuration store (self test parameters) of this subsystem
     */
    public IConfigStore getSelfTestConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves description associated with an individual self test.
     * This method may return null.
     * <P>
     *
     * @param locale locale of the client that requests the description
     * @return description of self test
     */
    public abstract String getSelfTestDescription(Locale locale);

    /**
     * Execute an individual self test.
     * <P>
     *
     * @param logger specifies logging subsystem
     * @exception ESelfTestException self test exception
     */
    public abstract void runSelfTest(ILogEventListener logger)
            throws ESelfTestException;
}
