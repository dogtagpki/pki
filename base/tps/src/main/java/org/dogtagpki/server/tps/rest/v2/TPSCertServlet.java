//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.tps.rest.base.TPSCertProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.tps.cert.TPSCertCollection;
import com.netscape.certsrv.tps.cert.TPSCertData;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsCert",
        urlPatterns = "/v2/certs/*")
public class TPSCertServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(TPSCertServlet.class);

    private TPSCertProcessor certProcessor;

    @Override
    public void init() throws ServletException {
        super.init();
        certProcessor = new TPSCertProcessor(getTPSEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findCerts(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSCertServlet.findCerts(): session: {}", session.getId());
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String filter = request.getParameter("filter");
        String tokenID = request.getParameter("tokenID");
        TPSCertCollection certs = certProcessor.findCerts(getAuthorizedProfiles(request), tokenID, filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(certs.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSCertServlet.getCert(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String certID = pathElement[0];
        TPSCertData cert = certProcessor.getCert(certID, getAuthorizedProfiles(request));
        PrintWriter out = response.getWriter();
        out.println(cert.toJSON());
    }
}
