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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.rest.v1;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.SelfTestCollection;
import com.netscape.certsrv.selftests.SelfTestData;
import com.netscape.certsrv.selftests.SelfTestResource;
import com.netscape.certsrv.selftests.SelfTestResult;
import com.netscape.certsrv.selftests.SelfTestResults;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.selftests.SelfTestSubsystem;

/**
 * @author Endi S. Dewata
 */
public class SelfTestService extends PKIService implements SelfTestResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SelfTestService.class);

    public SelfTestService() {
        logger.debug("SelfTestService.<init>()");
    }

    public SelfTestData createSelfTestData(SelfTestSubsystem subsystem, String selfTestID) throws UnsupportedEncodingException, EMissingSelfTestException {

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

        selfTestID = URLEncoder.encode(selfTestID, "UTF-8");

        return selfTestData;
    }

    @Override
    public Response findSelfTests(String filter, Integer start, Integer size) {

        logger.info("SelfTestService: Searching for selftests");
        logger.info("SelfTestService: - filter: " + filter);
        logger.info("SelfTestService: - start: " + start);
        logger.info("SelfTestService: - size: " + size);

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter too short: " + filter);
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        CMSEngine engine = getCMSEngine();
        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            logger.info("SelfTestService: Results:");
            // filter self tests
            Collection<String> results = new ArrayList<>();
            for (String name : subsystem.getSelfTestNames()) {
                if (filter != null && !name.contains(filter)) continue;
                logger.info("SelfTestService: - " + name);
                results.add(name);
            }

            SelfTestCollection response = new SelfTestCollection();
            Iterator<String> entries = results.iterator();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && entries.hasNext(); i++) entries.next();

            // return entries up to the page size
            for ( ; i<start+size && entries.hasNext(); i++) {
                SelfTestData data = createSelfTestData(subsystem, entries.next());
                response.addEntry(data);
            }

            // count the total entries
            for ( ; entries.hasNext(); i++) entries.next();
            response.setTotal(i);

            return createOKResponse(response);

        } catch (Exception e) {
            logger.error("SelfTestService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response getSelfTest(String selfTestID) {

        logger.info("SelfTestService: Retrieving selftest " + selfTestID);

        if (selfTestID == null) throw new BadRequestException("Missing selftest ID");

        CMSEngine engine = getCMSEngine();
        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            return createOKResponse(createSelfTestData(subsystem, selfTestID));

        } catch (Exception e) {
            logger.error("SelfTestService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response executeSelfTests(String action) {

        logger.info("SelfTestService: Executing selftest " + action);

        if (action == null) throw new BadRequestException("Missing selftest action");

        if (!"run".equals(action)) {
            throw new BadRequestException("Invalid action: " + action);
        }

        CMSEngine engine = getCMSEngine();
        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            subsystem.runSelfTestsOnDemand();

        } catch (Exception e) {
            logger.error("SelfTestService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }

        return createNoContentResponse();
    }

    @Override
    public Response runSelfTests() {

        logger.info("SelfTestService: Running all selftests");

        SelfTestResults results = new SelfTestResults();

        CMSEngine engine = getCMSEngine();
        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            for (String selfTestID : subsystem.listSelfTestsEnabledOnDemand()) {
                Response response = runSelfTest(selfTestID);
                SelfTestResult result = (SelfTestResult)response.getEntity();
                results.addEntry(result);
            }

        } catch (Exception e) {
            logger.error("SelfTestService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage());
        }

        return createOKResponse(results);
    }

    @Override
    public Response runSelfTest(String selfTestID) {

        logger.info("SelfTestService: Running selftest " + selfTestID);

        SelfTestResult result = new SelfTestResult();
        result.setID(selfTestID);

        CMSEngine engine = getCMSEngine();
        SelfTestSubsystem subsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

        try {
            subsystem.runSelfTest(selfTestID);
            result.setStatus("PASSED");

        } catch (Exception e) {

            logger.error("SelfTestService: " + e.getMessage(), e);

            result.setStatus("FAILED");

            StringWriter sw = new StringWriter();
            PrintWriter out = new PrintWriter(sw);
            e.printStackTrace(out);
            result.setOutput(sw.toString());
        }

        logger.info("SelfTestService: Status: " + result.getStatus());

        return createOKResponse(result);
    }
}
