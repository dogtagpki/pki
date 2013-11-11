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

package com.netscape.cmscore.selftests;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.certsrv.selftests.SelfTestCollection;
import com.netscape.certsrv.selftests.SelfTestData;
import com.netscape.certsrv.selftests.SelfTestResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class SelfTestService extends PKIService implements SelfTestResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public SelfTestService() {
        CMS.debug("SelfTestService.<init>()");
    }

    public SelfTestData createSelfTestData(ISelfTestSubsystem subsystem, String selfTestID) throws UnsupportedEncodingException, EMissingSelfTestException {

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
        URI uri = uriInfo.getBaseUriBuilder().path(SelfTestResource.class).path("{selfTestID}").build(selfTestID);
        selfTestData.setLink(new Link("self", uri));

        return selfTestData;
    }

    @Override
    public SelfTestCollection findSelfTests(Integer start, Integer size) {

        CMS.debug("SelfTestService.findSelfTests()");

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            ISelfTestSubsystem subsystem = (ISelfTestSubsystem)CMS.getSubsystem(ISelfTestSubsystem.ID);
            Iterator<String> entries = Arrays.asList(subsystem.listSelfTestsEnabledOnDemand()).iterator();

            SelfTestCollection response = new SelfTestCollection();
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

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public SelfTestData getSelfTest(String selfTestID) {

        if (selfTestID == null) throw new BadRequestException("Self test ID is null.");

        CMS.debug("SelfTestService.getSelfTest(\"" + selfTestID + "\")");

        try {
            ISelfTestSubsystem subsystem = (ISelfTestSubsystem)CMS.getSubsystem(ISelfTestSubsystem.ID);
            return createSelfTestData(subsystem, selfTestID);

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void executeSelfTests(String action) {

        if (action == null) throw new BadRequestException("Action is null.");

        CMS.debug("SelfTestService.executeSelfTests(\"" + action + "\")");

        if (!"run".equals(action)) {
            throw new BadRequestException("Invalid action: " + action);
        }

        try {
            ISelfTestSubsystem subsystem = (ISelfTestSubsystem)CMS.getSubsystem(ISelfTestSubsystem.ID);
            subsystem.runSelfTestsOnDemand();

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }
}
