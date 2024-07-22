//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.rest.base.SelfTestServletBase;
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
public class SelfTestServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(SelfTestServlet.class);

    private SelfTestServletBase selfTestServletBase;

    @Override
    public void init() throws ServletException {
        super.init();
        selfTestServletBase = new SelfTestServletBase(getEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findTests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.findTests(): session: {}", session.getId());
        String filter = request.getParameter("filter");
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        SelfTestCollection tests = selfTestServletBase.findSelfTests(filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(tests.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getTest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.getTest(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String selfTestId = pathElement[0];
        SelfTestData test = selfTestServletBase.getSelfTest(selfTestId);
        PrintWriter out = response.getWriter();
        out.println(test.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void executeTests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.executeTests(): session: {}", session.getId());
        String action = request.getParameter("action");
        selfTestServletBase.executeSelfTests(action);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.POST, paths = {"run"})
    public void runTests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.runTests(): session: {}", session.getId());
        SelfTestResults results = selfTestServletBase.runSelfTests();
        PrintWriter out = response.getWriter();
        out.println(results.toJSON());

    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/run"})
    public void runTest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServlet.runTest(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String testId = pathElement[0];
        SelfTestResult result = selfTestServletBase.runSelfTest(testId);
        PrintWriter out = response.getWriter();
        out.println(result.toJSON());
    }
}
