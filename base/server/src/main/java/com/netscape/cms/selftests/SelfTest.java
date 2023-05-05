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

import com.netscape.certsrv.logging.LogEventListener;
import com.netscape.certsrv.selftests.EDuplicateSelfTestException;
import com.netscape.certsrv.selftests.EInvalidSelfTestException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

//////////////////////
// class definition //
//////////////////////

/**
 * This class implements an individual self test.
 *
 * @author mharmsen
 * @author thomask
 */
public abstract class SelfTest {

    public static final String PROP_PLUGIN = "plugin";
    private static final String SELF_TEST_NAME = "SelfTest";

    protected CMSEngine engine;
    protected SelfTestSubsystem mSelfTestSubsystem;
    protected String mInstanceName = null;
    protected SelfTestPluginConfig mConfig;
    protected String mPrefix = null;

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    /**
     * Initializes this subsystem with the configuration store
     * associated with this instance name.
     *
     * @param subsystem the associated subsystem
     * @param instanceName the name of this self test instance
     * @param parameters configuration store (self test parameters)
     * @exception EDuplicateSelfTestException subsystem has duplicate name/value
     * @exception EInvalidSelfTestException subsystem has invalid name/value
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    public void initSelfTest(SelfTestSubsystem subsystem,
            String instanceName,
            ConfigStore parameters)
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

        mConfig = parameters.getSubStore(pluginPath, SelfTestPluginConfig.class);

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
     *
     * @exception ESelfTestException failed to start
     */
    public abstract void startupSelfTest()
            throws ESelfTestException;

    /**
     * Stops this subsystem. The subsystem may call shutdownSelfTest
     * anytime after initialization.
     */
    public abstract void shutdownSelfTest();

    /**
     * Returns the name associated with this self test. This method may
     * return null if the self test has not been initialized.
     *
     * @return instanceName of this self test
     */
    public String getSelfTestName() {
        return mInstanceName;
    }

    /**
     * Returns the root configuration storage (self test parameters)
     * associated with this subsystem.
     *
     * @return configuration store (self test parameters) of this subsystem
     */
    public ConfigStore getSelfTestConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves description associated with an individual self test.
     * This method may return null.
     *
     * @param locale locale of the client that requests the description
     * @return description of self test
     */
    public abstract String getSelfTestDescription(Locale locale);

    /**
     * Execute an individual self test.
     *
     * @param logger specifies logging subsystem
     * @exception Exception self test exception
     */
    public abstract void runSelfTest(LogEventListener logger) throws Exception;
}
