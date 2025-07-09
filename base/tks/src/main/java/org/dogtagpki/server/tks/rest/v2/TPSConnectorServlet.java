//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.rest.v2;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.stream.Collectors;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.server.tks.rest.base.TPSConnectorProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorCollection;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tksTPSConnector",
        urlPatterns = "/v2/admin/tps-connectors/*")
public class TPSConnectorServlet extends TKSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(TPSConnectorServlet.class);

    private TPSConnectorProcessor tpsConnector;

    @Override
    public void init() throws ServletException {
        super.init();
        tpsConnector = new TPSConnectorProcessor(engine);
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findConnectors(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.findConnectors(): session: {}", session.getId());
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String host = request.getParameter("host");
        String port = request.getParameter("port");
        TPSConnectorCollection connectors = tpsConnector.findConnectors(host, port, start, size);
        PrintWriter out = response.getWriter();
        out.println(connectors.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void createConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.createConnector(): session: {}", session.getId());
        String host = request.getParameter("host");
        String port = request.getParameter("port");
        TPSConnectorData newConnector = tpsConnector.createConnector(request.getUserPrincipal(), host, port);
        response.setStatus(HttpServletResponse.SC_CREATED);
        String encodedID = URLEncoder.encode(newConnector.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedID);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(newConnector.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {""})
    public void deleteConnectorByHost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.deleteConnectorByHost(): session: {}", session.getId());
        String host = request.getParameter("host");
        String port = request.getParameter("port");
        tpsConnector.deleteConnector(host, port);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.getConnector(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String id = pathElement[0];
        TPSConnectorData connector = tpsConnector.getConnector(id);
        PrintWriter out = response.getWriter();
        out.println(connector.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}"})
    public void modifyConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.modifyConnector(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String id = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        TPSConnectorData data = JSONSerializer.fromJSON(requestData, TPSConnectorData.class);
        TPSConnectorData connector = tpsConnector.updateConnector(id, data);
        PrintWriter out = response.getWriter();
        out.println(connector.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void deleteConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.deleteConnector(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String id = pathElement[0];
        tpsConnector.deleteConnector(id);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/shared-secret"})
    public void getSharedSecret(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.getSharedSecret(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String id = pathElement[0];
        KeyData key = tpsConnector.getSharedSecret(request.getUserPrincipal(), id);
        if (key == null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        PrintWriter out = response.getWriter();
        out.println(key.toJSON());

    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/shared-secret"})
    public void createSharedSecret(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.createSharedSecret(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String id = pathElement[0];
        KeyData key = tpsConnector.createSharedSecret(request.getUserPrincipal(), id);
        if (key == null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        PrintWriter out = response.getWriter();
        out.println(key.toJSON());
    }

    @WebAction(method = HttpMethod.PUT, paths = {"{}/shared-secret"})
    public void replaceSharedSecret(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.replaceSharedSecret(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String id = pathElement[0];
        KeyData key = tpsConnector.replaceSharedSecret(request.getUserPrincipal(), id);
        if (key == null) {
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        PrintWriter out = response.getWriter();
        out.println(key.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}/shared-secret"})
    public void deleteSharedSecret(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSConnectorServlet.deleteSharedSecret(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String id = pathElement[0];
        tpsConnector.deleteSharedSecret(id);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
