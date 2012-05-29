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

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.ListIterator;
import java.util.StringTokenizer;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogger;
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
 * This class implements a container for self tests.
 * <P>
 *
 * @author mharmsen
 * @author thomask
 * @version $Revision$, $Date$
 */
public class SelfTestSubsystem
        implements ISelfTestSubsystem {
    ////////////////////////
    // default parameters //
    ////////////////////////

    ///////////////////////
    // helper parameters //
    ///////////////////////

    //////////////////////////////////
    // SelfTestSubsystem parameters //
    //////////////////////////////////

    @SuppressWarnings("unused")
    private ISubsystem mOwner;
    private IConfigStore mConfig = null;
    private ILogEventListener mLogger = null;
    private ILogger mErrorLogger = CMS.getLogger();
    private ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    private String mRootPrefix = null;
    private String mPrefix = null;

    public Hashtable<String, ISelfTest> mSelfTestInstances = new Hashtable<String, ISelfTest>();
    public Vector<SelfTestOrderedInstance> mOnDemandOrder = new Vector<SelfTestOrderedInstance>();
    public Vector<SelfTestOrderedInstance> mStartupOrder = new Vector<SelfTestOrderedInstance>();

    ///////////////////////////
    // ISubsystem parameters //
    ///////////////////////////

    private static final String LIST_DELIMITER = ",";

    private static final String ELEMENT_DELIMITER = ":";
    private static final String CRITICAL = "critical";

    private static final String LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION =
            "LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION_2";

    /////////////////////
    // default methods //
    /////////////////////

    ////////////////////
    // helper methods //
    ////////////////////

    /**
     * Signed Audit Log
     *
     * This helper method is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    private void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    /**
     * This helper method returns the "full" property name (the corresponding
     * substore name prepended in front of the plugin/parameter name). This
     * method may return null.
     * <P>
     *
     * @param instancePrefix full name of configuration store
     * @param instanceName instance name of self test
     * @return fullname of this self test plugin
     */
    private String getFullName(String instancePrefix,
            String instanceName) {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instancePrefix != null) {
            instancePrefix = instancePrefix.trim();
        }
        if (instanceName != null) {
            instanceName = instanceName.trim();
        }

        if ((instancePrefix != null) &&
                (instancePrefix != "")) {
            if ((instanceName != null) &&
                    (instanceName != "")) {
                instanceFullName = instancePrefix
                        + "."
                        + instanceName;
            }
        } else {
            instanceFullName = instanceName;
        }

        return instanceFullName;
    }

    /**
     * This helper method checks to see if an instance name/value
     * pair exists for the corresponding ordered list element.
     * <P>
     *
     * @param element owner of this subsystem
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name/value
     */
    private void checkInstance(SelfTestOrderedInstance element)
            throws EInvalidSelfTestException, EMissingSelfTestException {
        String instanceFullName = null;
        String instanceName = null;
        String instanceValue = null;

        String instancePath = PROP_CONTAINER + "." + PROP_INSTANCE;
        IConfigStore instanceConfig = mConfig.getSubStore(instancePath);

        instanceName = element.getSelfTestName();
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        try {
            // extract the self test plugin value(s)
            instanceValue = instanceConfig.getString(instanceName);

            if ((instanceValue == null) ||
                    (instanceValue.equals(""))) {
                // self test plugin instance property name exists,
                // but it contains no value(s)
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_MISSING_VALUES",
                                instanceFullName));

                throw new EMissingSelfTestException(instanceFullName,
                        instanceValue);
            } else {
                instanceValue = instanceValue.trim();
            }

        } catch (EPropertyNotFound e) {
            // self test plugin instance property name is not present
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                            instanceFullName));

            throw new EMissingSelfTestException(instanceFullName);
        } catch (EBaseException e) {
            // self test plugin instance EBaseException
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_THREW_EBASEEXCEPTION",
                            instanceFullName,
                            instanceValue));

            throw new EInvalidSelfTestException(instanceFullName,
                    instanceValue);
        }
    }

    ///////////////////////////////
    // SelfTestSubsystem methods //
    ///////////////////////////////

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
    public String[] listSelfTestsEnabledOnDemand() {
        String[] mList;

        int numElements = mOnDemandOrder.size();

        if (numElements != 0) {
            mList = new String[numElements];
        } else {
            return null;
        }

        // loop through all self test plugin instances
        // specified to be executed on demand
        Enumeration<SelfTestOrderedInstance> instances = mOnDemandOrder.elements();

        int i = 0;

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            mList[i] = instance.getSelfTestName();
            if (mList[i] != null) {
                mList[i] = mList[i].trim();
            }
            i++;
        }

        return mList;
    }

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
    public void enableSelfTestOnDemand(String instanceName,
            boolean isCritical)
            throws EInvalidSelfTestException, EMissingSelfTestException {
        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed on demand
        Enumeration<SelfTestOrderedInstance> instances = mOnDemandOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                instance.setSelfTestCriticalMode(isCritical);
                return;
            }
        }

        // append a new element to the on-demand ordered list
        String elementName = null;

        if (isCritical) {
            elementName = instanceName
                    + ELEMENT_DELIMITER
                    + CRITICAL;
        } else {
            elementName = instanceName;
        }

        SelfTestOrderedInstance element;

        element = new SelfTestOrderedInstance(elementName);

        // SANITY CHECK:  find the corresponding instance property
        //                name for this self test plugin
        checkInstance(element);

        // store this self test plugin in on-demand order
        mOnDemandOrder.add(element);
    }

    /**
     * Disable the specified self test from being able to be executed on demand.
     * <P>
     *
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public void disableSelfTestOnDemand(String instanceName)
            throws EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed on demand
        Enumeration<SelfTestOrderedInstance> instances = mOnDemandOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                mOnDemandOrder.remove(instance);
                return;
            }
        }

        // self test plugin instance property name is not present
        log(mLogger,
                CMS.getLogMessage(
                        "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                        instanceFullName));

        throw new EMissingSelfTestException(instanceFullName);
    }

    /**
     * Determine if the specified self test is enabled to be executed on demand.
     * <P>
     *
     * @param instanceName instance name of self test
     * @return true if the specified self test is enabled on demand
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public boolean isSelfTestEnabledOnDemand(String instanceName)
            throws EMissingSelfTestException {
        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed on demand
        Enumeration<SelfTestOrderedInstance> instances = mOnDemandOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                return true;
            }
        }

        return false;
    }

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
            throws EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed on demand
        Enumeration<SelfTestOrderedInstance> instances = mOnDemandOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                if (instance.isSelfTestCritical()) {
                    return true;
                } else {
                    return false;
                }
            }
        }

        // self test plugin instance property name is not present
        log(mLogger,
                CMS.getLogMessage(
                        "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                        instanceFullName));

        throw new EMissingSelfTestException(instanceFullName);
    }

    /**
     * Execute all self tests specified to be run on demand.
     * <P>
     *
     * @exception EMissingSelfTestException subsystem has missing name
     * @exception ESelfTestException self test exception
     */
    public void runSelfTestsOnDemand()
            throws EMissingSelfTestException, ESelfTestException {
        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::runSelfTestsOnDemand():"
                    + "  ENTERING . . .");
        }

        // loop through all self test plugin instances
        // specified to be executed on demand
        Enumeration<SelfTestOrderedInstance> instances = mOnDemandOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            String instanceFullName = null;
            String instanceName = instance.getSelfTestName();

            if (instanceName != null) {
                instanceName = instanceName.trim();
                instanceFullName = getFullName(mPrefix,
                            instanceName);
            } else {
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

                throw new EMissingSelfTestException();
            }

            if (mSelfTestInstances.containsKey(instanceName)) {
                ISelfTest test = mSelfTestInstances.get(instanceName);

                try {
                    if (CMS.debugOn()) {
                        CMS.debug("SelfTestSubsystem::runSelfTestsOnDemand():"
                                + "    running \""
                                + test.getSelfTestName()
                                + "\"");
                    }

                    test.runSelfTest(mLogger);
                } catch (ESelfTestException e) {
                    // Check to see if the self test was critical:
                    if (isSelfTestCriticalOnDemand(instanceName)) {
                        log(mLogger,
                                CMS.getLogMessage(
                                        "CMSCORE_SELFTESTS_RUN_ON_DEMAND_FAILED",
                                        instanceFullName));

                        // shutdown the system gracefully
                        CMS.shutdown();

                        return;
                    }
                }
            } else {
                // self test plugin instance property name is not present
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                                instanceFullName));

                throw new EMissingSelfTestException(instanceFullName);
            }
        }

        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::runSelfTestsOnDemand():"
                    + "  EXITING.");
        }
    }

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
    public String[] listSelfTestsEnabledAtStartup() {
        String[] mList;

        int numElements = mStartupOrder.size();

        if (numElements != 0) {
            mList = new String[numElements];
        } else {
            return null;
        }

        // loop through all self test plugin instances
        // specified to be executed at server startup
        Enumeration<SelfTestOrderedInstance> instances = mStartupOrder.elements();

        int i = 0;

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            mList[i] = instance.getSelfTestName();
            if (mList[i] != null) {
                mList[i] = mList[i].trim();
            }
            i++;
        }

        return mList;
    }

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
    public void enableSelfTestAtStartup(String instanceName,
            boolean isCritical)
            throws EInvalidSelfTestException, EMissingSelfTestException {
        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed at server startup
        Enumeration<SelfTestOrderedInstance> instances = mStartupOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                instance.setSelfTestCriticalMode(isCritical);
                return;
            }
        }

        // append a new element to the startup ordered list
        String elementName = null;

        if (isCritical) {
            elementName = instanceName
                    + ELEMENT_DELIMITER
                    + CRITICAL;
        } else {
            elementName = instanceName;
        }

        SelfTestOrderedInstance element;

        element = new SelfTestOrderedInstance(elementName);

        // SANITY CHECK:  find the corresponding instance property
        //                name for this self test plugin
        checkInstance(element);

        // store this self test plugin in startup order
        mStartupOrder.add(element);
    }

    /**
     * Disable the specified self test at server startup.
     * <P>
     *
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public void disableSelfTestAtStartup(String instanceName)
            throws EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed at server startup
        Enumeration<SelfTestOrderedInstance> instances = mStartupOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                mStartupOrder.remove(instance);
                return;
            }
        }

        // self test plugin instance property name is not present
        log(mLogger,
                CMS.getLogMessage(
                        "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                        instanceFullName));

        throw new EMissingSelfTestException(instanceFullName);
    }

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
            throws EMissingSelfTestException {
        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed at server startup
        Enumeration<SelfTestOrderedInstance> instances = mStartupOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                return true;
            }
        }

        return false;
    }

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
            throws EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // loop through all self test plugin instances
        // specified to be executed at server startup
        Enumeration<SelfTestOrderedInstance> instances = mStartupOrder.elements();

        while (instances.hasMoreElements()) {
            SelfTestOrderedInstance instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                if (instance.isSelfTestCritical()) {
                    return true;
                } else {
                    return false;
                }
            }
        }

        // self test plugin instance property name is not present
        log(mLogger,
                CMS.getLogMessage(
                        "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                        instanceFullName));

        throw new EMissingSelfTestException(instanceFullName);
    }

    /**
     * Execute all self tests specified to be run at server startup.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION used when self tests are run at server startup
     * </ul>
     *
     * @exception EMissingSelfTestException subsystem has missing name
     * @exception ESelfTestException self test exception
     */
    public void runSelfTestsAtStartup()
            throws EMissingSelfTestException, ESelfTestException {
        String auditMessage = null;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (CMS.debugOn()) {
                CMS.debug("SelfTestSubsystem::runSelfTestsAtStartup():"
                        + "  ENTERING . . .");
            }

            // loop through all self test plugin instances
            // specified to be executed at server startup
            Enumeration<SelfTestOrderedInstance> instances = mStartupOrder.elements();

            while (instances.hasMoreElements()) {
                SelfTestOrderedInstance instance = instances.nextElement();

                String instanceFullName = null;
                String instanceName = instance.getSelfTestName();

                if (instanceName != null) {
                    instanceName = instanceName.trim();
                    instanceFullName = getFullName(mPrefix,
                                instanceName);
                } else {
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                                ILogger.SYSTEM_UID,
                                ILogger.FAILURE);

                    audit(auditMessage);

                    throw new EMissingSelfTestException();
                }

                if (mSelfTestInstances.containsKey(instanceName)) {
                    ISelfTest test = mSelfTestInstances.get(instanceName);

                    try {
                        if (CMS.debugOn()) {
                            CMS.debug("SelfTestSubsystem::runSelfTestsAtStartup():"
                                    + "    running \""
                                    + test.getSelfTestName()
                                    + "\"");
                        }

                        test.runSelfTest(mLogger);
                    } catch (ESelfTestException e) {
                        // Check to see if the self test was critical:
                        if (isSelfTestCriticalAtStartup(instanceName)) {
                            log(mLogger,
                                    CMS.getLogMessage(
                                            "CMSCORE_SELFTESTS_RUN_AT_STARTUP_FAILED",
                                            instanceFullName));

                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                                        ILogger.SYSTEM_UID,
                                        ILogger.FAILURE);

                            audit(auditMessage);

                            // shutdown the system gracefully
                            CMS.shutdown();

                            return;
                        }
                    }
                } else {
                    // self test plugin instance property name is not present
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                                    instanceFullName));

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                                ILogger.SYSTEM_UID,
                                ILogger.FAILURE);

                    audit(auditMessage);

                    throw new EMissingSelfTestException(instanceFullName);
                }
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                        ILogger.SYSTEM_UID,
                        ILogger.SUCCESS);

            audit(auditMessage);

            if (CMS.debugOn()) {
                CMS.debug("SelfTestSubsystem::runSelfTestsAtStartup():"
                        + "  EXITING.");
            }
        } catch (EMissingSelfTestException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                        ILogger.SYSTEM_UID,
                        ILogger.FAILURE);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        }
    }

    public void log(int level, String msg) {
    }

    //
    // methods associated with the list of self test instances
    //

    /**
     * Retrieve an individual self test from the instances list
     * given its instance name. This method may return null.
     * <P>
     *
     * @param instanceName instance name of self test
     * @return individual self test
     */
    public ISelfTest getSelfTest(String instanceName) {
        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
        } else {
            return null;
        }

        // loop through all self test plugin instances
        Enumeration<ISelfTest> instances = mSelfTestInstances.elements();

        while (instances.hasMoreElements()) {
            ISelfTest instance = instances.nextElement();

            if (instanceName.equals(instance.getSelfTestName())) {
                return instance;
            }
        }

        return null;
    }

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
    public ILogEventListener getSelfTestLogger() {
        return mLogger;
    }

    /**
     * This method represents the log interface for the self test subsystem.
     * <P>
     *
     * @param logger log event listener
     * @param msg self test log message
     */
    public void log(ILogEventListener logger, String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (logger != null) {
            // log the message to the "selftests.log" log
            AuditEvent ev = new AuditEvent(msg);

            ev.setSource(ILogger.S_OTHER);
            ev.setLevel(ILogger.LL_INFO);
            try {
                logger.log(ev);
            } catch (ELogException le) {
                // log the message to the "transactions" log
                mErrorLogger.log(ILogger.EV_AUDIT,
                        null,
                        ILogger.S_OTHER,
                        ILogger.LL_INFO,
                        msg + " - " + le.toString());
            }
        } else {
            // log the message to the "transactions" log
            mErrorLogger.log(ILogger.EV_AUDIT,
                    null,
                    ILogger.S_OTHER,
                    ILogger.LL_INFO,
                    msg);
        }
    }

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
    public void registerSelfTestOnDemand(String instanceName,
            boolean isCritical,
            ISelfTest instance)
            throws EDuplicateSelfTestException,
            EInvalidSelfTestException,
            EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        if (mSelfTestInstances.containsKey(instanceName)) {
            // self test plugin instance property name is a duplicate
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_DUPLICATE_NAME",
                            instanceFullName));

            throw new EDuplicateSelfTestException(instanceFullName);
        } else {
            // append this self test plugin instance to the end of the list
            mSelfTestInstances.put(instanceName, instance);
        }

        // register the individual self test on the "on demand" list
        enableSelfTestOnDemand(instanceName, isCritical);
    }

    /**
     * Deregister an individual self test on the instances list AND
     * on the "on demand" list (note that the specified self test
     * will be removed from each list).
     * <P>
     *
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public void deregisterSelfTestOnDemand(String instanceName)
            throws EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // deregister the individual self test from the instances list
        ISelfTest test = getSelfTest(instanceName);

        if (test == null) {
            // self test plugin instance property name is not present
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                            instanceFullName));

            throw new EMissingSelfTestException(instanceFullName);
        } else {
            // append this self test plugin instance to the end of the list
            mSelfTestInstances.remove(instanceName);
        }

        // deregister the individual self test from the "on demand" list
        disableSelfTestOnDemand(instanceName);
    }

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
    public void registerSelfTestAtStartup(String instanceName,
            boolean isCritical,
            ISelfTest instance)
            throws EDuplicateSelfTestException,
            EInvalidSelfTestException,
            EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        if (mSelfTestInstances.containsKey(instanceName)) {
            // self test plugin instance property name is a duplicate
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_DUPLICATE_NAME",
                            instanceFullName));

            throw new EDuplicateSelfTestException(instanceFullName);
        } else {
            // append this self test plugin instance to the end of the list
            mSelfTestInstances.put(instanceName, instance);
        }

        // register the individual self test on the "startup" list
        enableSelfTestAtStartup(instanceName, isCritical);
    }

    /**
     * Deregister an individual self test on the instances list AND
     * on the "startup" list (note that the specified self test
     * will be removed from each list).
     * <P>
     *
     * @param instanceName instance name of self test
     * @exception EMissingSelfTestException subsystem has missing name
     */
    public void deregisterSelfTestAtStartup(String instanceName)
            throws EMissingSelfTestException {
        String instanceFullName = null;

        // strip preceding/trailing whitespace
        // from passed-in String parameters
        if (instanceName != null) {
            instanceName = instanceName.trim();
            instanceFullName = getFullName(mPrefix,
                        instanceName);
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        // deregister the individual self test from the instances list
        ISelfTest test = getSelfTest(instanceName);

        if (test == null) {
            // self test plugin instance property name is not present
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_MISSING_NAME",
                            instanceFullName));

            throw new EMissingSelfTestException(instanceFullName);
        } else {
            // append this self test plugin instance to the end of the list
            mSelfTestInstances.remove(instanceName);
        }

        // deregister the individual self test from the "startup" list
        disableSelfTestAtStartup(instanceName);
    }

    ////////////////////////
    // ISubsystem methods //
    ////////////////////////

    /**
     * This method retrieves the name of this subsystem. This method
     * may return null.
     * <P>
     *
     * @return identification of this subsystem
     */
    public String getId() {
        return ID;
    }

    /**
     * This method sets information specific to this subsystem.
     * <P>
     *
     * @param id identification of this subsystem
     * @exception EBaseException base CMS exception
     */
    public void setId(String id)
            throws EBaseException {

        if (id == null) {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EBaseException("id is null");
        }

        // nothing needs to be done
    }

    /**
     * This method initializes this subsystem.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     * @exception EBaseException base CMS exception
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::init():"
                    + "  ENTERING . . .");
        }

        if (config == null) {
            CMS.debug("SelfTestSubsystem::init() - config is null!");
            throw new EBaseException("config is null");
        }

        mOwner = owner;
        mConfig = config;

        if ((mConfig != null) &&
                (mConfig.getName() != null) &&
                (mConfig.getName() != "")) {
            mRootPrefix = mConfig.getName().trim();
        }

        int loadStatus = 0;

        // NOTE:  Obviously, we must load the self test logger parameters
        //        first, since the "selftests.log" log file does not
        //        exist until this is accomplished!!!

        ////////////////////////////////////
        // loggerPropertyName=loggerValue //
        ////////////////////////////////////

        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::init():"
                    + "    loading self test logger parameters");
        }

        String loggerPrefix = null;
        String loggerFullName = null;
        String loggerName = PROP_LOGGER_CLASS;
        String loggerValue = null;

        // compose self test plugins logger property prefix
        String loggerPath = PROP_CONTAINER + "." + PROP_LOGGER;
        IConfigStore loggerConfig = mConfig.getSubStore(loggerPath);

        if ((loggerConfig != null) &&
                (loggerConfig.getName() != null) &&
                (loggerConfig.getName() != "")) {
            loggerPrefix = loggerConfig.getName().trim();
        } else {
            // NOTE:  These messages can only be logged to the "transactions"
            //        log, since the "selftests.log" will not exist!
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_INITIALIZATION_NOTIFICATION"));

            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        Enumeration<String> loggerInstances = loggerConfig.getPropertyNames();

        if (loggerInstances.hasMoreElements()) {
            loadStatus++;

            try {
                loggerFullName = getFullName(loggerPrefix,
                            loggerName);

                // retrieve the associated logger class
                loggerValue = loggerConfig.getString(loggerName);
                if (loggerValue != null) {
                    loggerValue = loggerValue.trim();
                } else {
                    // self test plugin instance property name exists,
                    // but it contains no value(s)

                    // NOTE:  This message can only be logged to the
                    //        "transactions" log, since the "selftests.log"
                    //        will not exist!
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_PROPERTY_MISSING_VALUES",
                                    loggerFullName));

                    throw new EMissingSelfTestException(loggerFullName,
                            loggerValue);
                }

                Object o = Class.forName(loggerValue).newInstance();

                if (!(o instanceof ILogEventListener)) {
                    // NOTE:  These messages can only be logged to the
                    //        "transactions" log, since the "selftests.log"
                    //        will not exist!
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_INITIALIZATION_NOTIFICATION"));

                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_PROPERTY_INVALID_INSTANCE",
                                    loggerFullName,
                                    loggerValue));

                    throw new EInvalidSelfTestException(loggerFullName,
                            loggerValue);
                }

                // initialize the self tests logger
                mLogger = (ILogEventListener) o;
                mLogger.init(this, loggerConfig);
            } catch (EBaseException e) {
                // self test property name EBaseException

                // NOTE:  These messages can only be logged to the
                //        "transactions" log, since the "selftests.log"
                //        will not exist!
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_INITIALIZATION_NOTIFICATION"));

                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_THREW_EBASEEXCEPTION",
                                loggerFullName,
                                loggerValue));

                throw new EInvalidSelfTestException(loggerFullName,
                        loggerValue);
            } catch (Exception e) {
                // NOTE:  These messages can only be logged to the
                //        "transactions" log, since the "selftests.log"
                //        will not exist!
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_INITIALIZATION_NOTIFICATION"));

                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_THREW_EXCEPTION",
                                loggerFullName,
                                loggerValue));

                CMS.debugStackTrace();

                throw new EInvalidSelfTestException(loggerFullName,
                        loggerValue);
            }
        }

        // Barring any exceptions thrown above, we begin logging messages
        // to either the "transactions" log, or the "selftests.log" log.
        if (loadStatus == 0) {
            // NOTE:  These messages can only be logged to the
            //        "transactions" log, since the "selftests.log"
            //        will not exist!
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_INITIALIZATION_NOTIFICATION"));

            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_DONT_LOAD_LOGGER_PARAMETERS"));
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_INITIALIZATION_NOTIFICATION"));

            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_LOAD_LOGGER_PARAMETERS"));
        }

        ////////////////////////////////////////
        // instancePropertyName=instanceValue //
        ////////////////////////////////////////

        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::init():"
                    + "    loading self test plugins");
        }

        // compose self test plugins instance property prefix
        String instancePath = PROP_CONTAINER + "." + PROP_INSTANCE;
        IConfigStore instanceConfig = mConfig.getSubStore(instancePath);

        if ((instanceConfig != null) &&
                (instanceConfig.getName() != null) &&
                (instanceConfig.getName() != "")) {
            mPrefix = instanceConfig.getName().trim();
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

            throw new EMissingSelfTestException();
        }

        Enumeration<String> instances = instanceConfig.getPropertyNames();

        if (instances.hasMoreElements()) {
            loadStatus++;

            log(mLogger,
                    CMS.getLogMessage("CMSCORE_SELFTESTS_LOAD_PLUGINS"));
        } else {
            log(mLogger,
                    CMS.getLogMessage("CMSCORE_SELFTESTS_DONT_LOAD_PLUGINS"));
        }

        // load all self test plugin instances
        String instanceFullName = null;
        String instanceName = null;
        String instanceValue = null;
        boolean first_time = true;

        while (instances.hasMoreElements()) {
            // the instance property name should be unique
            instanceName = instances.nextElement();
            if (instanceName != null) {
                instanceName = instanceName.trim();
                instanceFullName = getFullName(mPrefix,
                            instanceName);
            } else {
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_NAME_IS_NULL"));

                throw new EMissingSelfTestException();
            }

            if (mSelfTestInstances.containsKey(instanceName)) {
                // self test plugin instance property name is a duplicate
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_DUPLICATE_NAME",
                                instanceFullName));

                throw new EDuplicateSelfTestException(instanceFullName);
            }

            // an associated instance property value, a class, must exist
            try {
                instanceValue = instanceConfig.getString(instanceName);
                if (instanceValue != null) {
                    instanceValue = instanceValue.trim();
                } else {
                    // self test plugin instance property name exists,
                    // but it contains no value(s)
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_PROPERTY_MISSING_VALUES",
                                    instanceFullName));

                    throw new EMissingSelfTestException(instanceFullName,
                            instanceValue);
                }
            } catch (EBaseException e) {
                // self test property name EBaseException
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_THREW_EBASEEXCEPTION",
                                instanceFullName,
                                instanceValue));

                throw new EInvalidSelfTestException(instanceFullName,
                        instanceValue);
            }

            // verify that the associated class is a valid instance of ISelfTest
            Object o;

            try {
                o = Class.forName(instanceValue).newInstance();

                if (!(o instanceof ISelfTest)) {
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_PROPERTY_INVALID_INSTANCE",
                                    instanceFullName,
                                    instanceValue));

                    throw new EInvalidSelfTestException(instanceFullName,
                            instanceValue);
                }
            } catch (Exception e) {
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PROPERTY_THREW_EXCEPTION",
                                instanceFullName,
                                instanceValue));

                CMS.debugStackTrace();

                throw new EInvalidSelfTestException(instanceFullName,
                        instanceValue);
            }

            // retrieve all ISelfTest parameters associated with this class
            try {
                if (first_time) {
                    first_time = false;

                    if (CMS.debugOn()) {
                        CMS.debug("SelfTestSubsystem::init():"
                                + "    loading self test plugin parameters");
                    }

                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_LOAD_PLUGIN_PARAMETERS"));
                }

                ISelfTest test = (ISelfTest) o;

                test.initSelfTest(this, instanceName, mConfig);

                // store this self test plugin instance
                mSelfTestInstances.put(instanceName, test);
            } catch (EDuplicateSelfTestException e) {
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PLUGIN_DUPLICATE_PARAMETER",
                                instanceFullName,
                                e.getInstanceParameter()));

                throw e;
            } catch (EMissingSelfTestException e) {
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PLUGIN_MISSING_PARAMETER",
                                instanceFullName,
                                e.getInstanceParameter()));

                throw e;
            } catch (EInvalidSelfTestException e) {
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_PLUGIN_INVALID_PARAMETER",
                                instanceFullName,
                                e.getInstanceParameter()));

                throw e;
            }
        }

        //////////////////////////////////////////////////////////
        // onDemandOrderPropertyName=onDemandOrderValue1, . . . //
        //////////////////////////////////////////////////////////

        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::init():"
                    + "    loading on demand self tests");
        }

        // compose self test plugins on-demand ordering property name
        String onDemandOrderName = PROP_CONTAINER + "."
                + PROP_ORDER + "."
                + PROP_ON_DEMAND;
        String onDemandOrderFullName = getFullName(mRootPrefix,
                onDemandOrderName);
        String onDemandOrderValues = null;

        try {
            // extract all self test plugins on-demand
            // ordering property values
            onDemandOrderValues = mConfig.getString(onDemandOrderName);
            if (onDemandOrderValues != null) {
                onDemandOrderValues = onDemandOrderValues.trim();
            }

            loadStatus++;

            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_LOAD_PLUGINS_ON_DEMAND"));

            if ((onDemandOrderValues == null) ||
                    (onDemandOrderValues.equals(""))) {
                // self test plugins on-demand ordering property name
                // exists, but it contains no values, which means that
                // no self tests are configured to run on-demand
                if ((onDemandOrderFullName != null) &&
                        (!onDemandOrderFullName.equals(""))) {
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_MISSING_ON_DEMAND_VALUES",
                                    onDemandOrderFullName));
                }
                throw new EBaseException("onDemandOrderValues is null "
                                        + "or empty");
            }

            StringTokenizer tokens = new StringTokenizer(onDemandOrderValues,
                    LIST_DELIMITER);

            while (tokens.hasMoreTokens()) {
                // create a new element in the on-demand ordered list
                SelfTestOrderedInstance element;

                element = new SelfTestOrderedInstance(
                            tokens.nextToken().trim());

                // SANITY CHECK:  find the corresponding instance property
                //                name for this self test plugin
                checkInstance(element);

                // store this self test plugin in on-demand order
                mOnDemandOrder.add(element);
            }

        } catch (EPropertyNotFound e) {
            // self test plugins on-demand ordering property name
            // is not present

            // presently, we merely log this fact
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_DONT_LOAD_PLUGINS_ON_DEMAND"));

            // throw new EMissingSelfTestException( onDemandOrderFullName );
        } catch (EBaseException e) {
            // self test property name EBaseException
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_THREW_EBASEEXCEPTION",
                            onDemandOrderFullName,
                            onDemandOrderValues));

            throw new EInvalidSelfTestException(onDemandOrderFullName,
                    onDemandOrderValues);
        }

        ////////////////////////////////////////////////////////
        // startupOrderPropertyName=startupOrderValue1, . . . //
        ////////////////////////////////////////////////////////

        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::init():"
                    + "    loading startup self tests");
        }

        // compose self test plugins startup ordering property name
        String startupOrderName = PROP_CONTAINER + "."
                + PROP_ORDER + "."
                + PROP_STARTUP;
        String startupOrderFullName = getFullName(mRootPrefix,
                startupOrderName);
        String startupOrderValues = null;

        try {
            // extract all self test plugins startup ordering
            // property values
            startupOrderValues = mConfig.getString(startupOrderName);
            if (startupOrderValues != null) {
                startupOrderValues = startupOrderValues.trim();
            }

            loadStatus++;

            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_LOAD_PLUGINS_AT_STARTUP"));

            if ((startupOrderValues == null) ||
                    (startupOrderValues.equals(""))) {
                // self test plugins startup ordering property name
                // exists, but it contains no values, which means that
                // no self tests are configured to run at server startup
                if ((startupOrderFullName != null) &&
                        (!startupOrderFullName.equals(""))) {
                    log(mLogger,
                            CMS.getLogMessage(
                                    "CMSCORE_SELFTESTS_MISSING_STARTUP_VALUES",
                                    startupOrderFullName));
                }
            }

            StringTokenizer tokens = new StringTokenizer(startupOrderValues,
                    LIST_DELIMITER);

            while (tokens.hasMoreTokens()) {
                // create a new element in the startup ordered list
                SelfTestOrderedInstance element;

                element = new SelfTestOrderedInstance(
                            tokens.nextToken().trim());

                // SANITY CHECK:  find the corresponding instance property
                //                name for this self test plugin
                checkInstance(element);

                // store this self test plugin in startup order
                mStartupOrder.add(element);
            }

        } catch (EPropertyNotFound e) {
            // self test plugins startup ordering property name is
            // not present

            // presently, we merely log this fact
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_DONT_LOAD_PLUGINS_AT_STARTUP"));

            // throw new EMissingSelfTestException( startupOrderFullName );
        } catch (EBaseException e) {
            // self test property name EBaseException
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PROPERTY_THREW_EBASEEXCEPTION",
                            startupOrderFullName,
                            startupOrderValues));

            throw new EInvalidSelfTestException(startupOrderFullName,
                    startupOrderValues);
        }

        // notify user whether or not self test plugins have been loaded
        if (loadStatus == 0) {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PLUGINS_NONE_LOADED"));
        } else {
            log(mLogger,
                    CMS.getLogMessage(
                            "CMSCORE_SELFTESTS_PLUGINS_LOADED"));
        }

        if (CMS.debugOn()) {
            CMS.debug("SelfTestSubsystem::init():"
                    + "  EXITING.");
        }
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     * <P>
     *
     * @exception EBaseException base CMS exception
     */
    public void startup()
            throws EBaseException {
        // loop through all self test plugin instances
        Enumeration<ISelfTest> instances = mSelfTestInstances.elements();

        while (instances.hasMoreElements()) {
            ISelfTest instance = instances.nextElement();

            instance.startupSelfTest();
        }

        if (!CMS.isPreOpMode()) {
            // run all self test plugin instances (designated at startup)
            Enumeration<SelfTestOrderedInstance> selftests = mStartupOrder.elements();

            if (selftests.hasMoreElements()) {
                // log that execution of startup self tests has begun
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_RUN_AT_STARTUP"));

                // execute all startup self tests
                runSelfTestsAtStartup();

                // log that execution of all "critical" startup self tests
                // has completed "successfully"
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_RUN_AT_STARTUP_SUCCEEDED"));
            } else {
                log(mLogger,
                        CMS.getLogMessage(
                                "CMSCORE_SELFTESTS_NOT_RUN_AT_STARTUP"));
            }
        }
    }

    /**
     * Stops this subsystem. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    public void shutdown() {
        // reverse order of all self test plugin instances
        Collection<ISelfTest> collection = mSelfTestInstances.values();
        Vector<ISelfTest> list = new Vector<ISelfTest>(collection);

        Collections.reverse(list);

        // loop through all self test plugin instances
        ListIterator<ISelfTest> instances = list.listIterator();

        while (instances.hasNext()) {
            ISelfTest instance = instances.next();

            instance.shutdownSelfTest();
        }
    }

    /**
     * Returns the root configuration storage of this subsystem.
     * This method may return null.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }
}
