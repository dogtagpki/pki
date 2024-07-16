//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.rest.v2.SelfTestServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.selftests.SelfTestCollection;
import com.netscape.certsrv.selftests.SelfTestData;
import com.netscape.certsrv.selftests.SelfTestResult;
import com.netscape.certsrv.selftests.SelfTestResults;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsSelfTests",
        urlPatterns = "/v2/selftests/*")
public class SelfTestServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(SelfTestServlet.class);

    @WebAction(method = HttpMethod.GET, paths = { "/"})
    public void findTests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.findTests(): session: {}", session.getId());
        String filter = request.getParameter("filter");
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        SelfTestServletBase selfTestServlet = new SelfTestServletBase(getTPSEngine());
        SelfTestCollection tests = selfTestServlet.findSelfTests(filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(tests.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = { "/{}"})
    public void getTest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.getTest(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String selfTestId = pathElement[0];
        SelfTestServletBase selfTestServlet = new SelfTestServletBase(getTPSEngine());
        SelfTestData test = selfTestServlet.getSelfTest(selfTestId);
        PrintWriter out = response.getWriter();
        out.println(test.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = { "/"})
    public void executeTests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.executeTests(): session: {}", session.getId());
        String action = request.getParameter("action");
        SelfTestServletBase selfTestServlet = new SelfTestServletBase(getTPSEngine());
        selfTestServlet.executeSelfTests(action);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.POST, paths = { "/run"})
    public void runTests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.runTests(): session: {}", session.getId());
        SelfTestServletBase selfTestServlet = new SelfTestServletBase(getTPSEngine());
        SelfTestResults results = selfTestServlet.runSelfTests();
        PrintWriter out = response.getWriter();
        out.println(results.toJSON());

    }

    @WebAction(method = HttpMethod.POST, paths = { "/{}/run"})
    public void runTest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.runTest(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String testId = pathElement[0];
        SelfTestServletBase selfTestServlet = new SelfTestServletBase(getTPSEngine());
        SelfTestResult result = selfTestServlet.runSelfTest(testId);
        PrintWriter out = response.getWriter();
        out.println(result.toJSON());
    }
}
