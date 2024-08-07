//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import java.io.PrintWriter;
import java.util.stream.Collectors;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Ade Lee
 */
@WebServlet(
        name = "caKraConnector",
        urlPatterns = "/v2/admin/kraconnector/*")
public class KRAConnectorServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(KRAConnectorServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getConnectorInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KRAConnectorServlet.getConnectorInfo(): session: {}", session.getId());
        KRAConnectorInfo connector = null;
        PrintWriter out = response.getWriter();
        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(request.getLocale());
            processor.setCMSEngine(engine);
            processor.init();
            connector = processor.getConnectorInfo();
        } catch (EBaseException e) {
            String message = "Unable to get KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
        out.println(connector.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"add"})
    public void addConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KRAConnectorServlet.addConnector(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        KRAConnectorInfo connector = JSONSerializer.fromJSON(requestData, KRAConnectorInfo.class);
        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(request.getLocale());
            processor.setCMSEngine(engine);
            processor.init();
            processor.addConnector(connector);
        } catch (EBaseException e) {
            String message = "Unable to add KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.POST, paths = {"remove"})
    public void removeConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KRAConnectorServlet.removeConnector(): session: {}", session.getId());
        String host = request.getParameter("host");
        String port = request.getParameter("port");

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(request.getLocale());
            processor.setCMSEngine(engine);
            processor.init();
            processor.removeConnector(host, port);
        } catch (EBaseException e) {
            String message = "Unable to remove KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.POST, paths = {"addHost"})
    public void addHost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KRAConnectorServlet.addHost(): session: {}", session.getId());
        String host = request.getParameter("host");
        String port = request.getParameter("port");
        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(request.getLocale());
            processor.setCMSEngine(engine);
            processor.init();
            processor.addHost(host, port);
        } catch (EBaseException e) {
            String message = "Unable to add KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
