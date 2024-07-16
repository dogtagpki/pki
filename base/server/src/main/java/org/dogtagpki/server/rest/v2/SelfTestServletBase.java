//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.SelfTestCollection;
import com.netscape.certsrv.selftests.SelfTestData;
import com.netscape.certsrv.selftests.SelfTestResult;
import com.netscape.certsrv.selftests.SelfTestResults;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class SelfTestServletBase {
    public static final Logger logger = LoggerFactory.getLogger(SelfTestServletBase.class);

    private CMSEngine engine;

    public SelfTestServletBase(CMSEngine engine) {
        this.engine = engine;
    }

    public SelfTestCollection findSelfTests(String filter, Integer start, Integer size) {

        logger.info("SelfTestServletBase: Searching for selftests");
        logger.info("SelfTestServletBase: - filter: {}", filter);
        logger.info("SelfTestServletBase: - start: {}", start);
        logger.info("SelfTestServletBase: - size: {}", size);

        if (filter != null && filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            logger.info("SelfTestServletBase: Results:");
            // filter self tests
            Collection<String> results = new ArrayList<>();
            for (String name : subsystem.getSelfTestNames()) {
                if (filter != null && !name.contains(filter)) continue;
                logger.info("SelfTestServletBase: - {}", name);
                results.add(name);
            }

            SelfTestCollection selfTests = new SelfTestCollection();
            Iterator<String> entries = results.iterator();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && entries.hasNext(); i++) entries.next();

            // return entries up to the page size
            for ( ; i<start+size && entries.hasNext(); i++) {
                SelfTestData data = createSelfTestData(subsystem, entries.next());
                selfTests.addEntry(data);
            }

            // count the total entries
            for ( ; entries.hasNext(); i++) entries.next();
            selfTests.setTotal(i);

            return selfTests;

        } catch (Exception e) {
            logger.error("SelfTestServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }
    }

    public SelfTestData getSelfTest(String selfTestID) {

        logger.info("SelfTestServletBase: Retrieving selftest {}", selfTestID);

        if (selfTestID == null || selfTestID.isBlank()) throw new BadRequestException("Missing selftest ID");

        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            return createSelfTestData(subsystem, selfTestID);

        } catch (Exception e) {
            logger.error("SelfTestServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }
    }

    private SelfTestData createSelfTestData(SelfTestSubsystem subsystem, String selfTestID) throws EMissingSelfTestException {

        SelfTestData selfTestData = new SelfTestData();
        selfTestData.setID(selfTestID);
        selfTestData.setEnabledAtStartup(subsystem.isSelfTestEnabledAtStartup(selfTestID));
        try {
            selfTestData.setCriticalAtStartup(subsystem.isSelfTestCriticalAtStartup(selfTestID));
        } catch (EMissingSelfTestException e) {
            // ignore
        }
        selfTestData.setEnabledOnDemand(subsystem.isSelfTestEnabledOnDemand(selfTestID));
        try {
            selfTestData.setCriticalOnDemand(subsystem.isSelfTestCriticalOnDemand(selfTestID));
        } catch (EMissingSelfTestException e) {
            // ignore
        }
        return selfTestData;
    }

    public void executeSelfTests(String action) {

        logger.info("SelfTestServletBase: Executing selftest {}", action);

        if (action == null || action.isBlank()) throw new BadRequestException("Missing selftest action");

        if (!"run".equals(action)) {
            throw new BadRequestException("Invalid action: " + action);
        }

        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            subsystem.runSelfTestsOnDemand();

        } catch (Exception e) {
            logger.error("SelfTestServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }
    }

    public SelfTestResults runSelfTests() {

        logger.info("SelfTestServletBase: Running all selftests");

        SelfTestResults results = new SelfTestResults();

        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            for (String selfTestID : subsystem.listSelfTestsEnabledOnDemand()) {
                SelfTestResult result = runSelfTest(selfTestID);
                results.addEntry(result);
            }

        } catch (Exception e) {
            logger.error("SelfTestServletBase: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }

        return results;
    }

    public SelfTestResult runSelfTest(String selfTestID) {

        logger.info("SelfTestServletBase: Running selftest {}", selfTestID);

        SelfTestResult result = new SelfTestResult();
        result.setID(selfTestID);

        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            subsystem.runSelfTest(selfTestID);
            result.setStatus("PASSED");

        } catch (Exception e) {

            logger.error("SelfTestServletBase: " + e.getMessage(), e);

            result.setStatus("FAILED");

            StringWriter sw = new StringWriter();
            PrintWriter out = new PrintWriter(sw);
            e.printStackTrace(out);
            result.setOutput(sw.toString());
        }
        logger.info("SelfTestServletBase: Status: {}", result.getStatus());

        return result;
    }
}
