//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.tps.rest.base.ConnectorProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.tps.connector.ConnectorCollection;
import com.netscape.certsrv.tps.connector.ConnectorData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsConnector",
        urlPatterns = "/v2/connectors/*")
public class ConnectorServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(ConnectorServlet.class);

    private ConnectorProcessor connectorProcessor;
    @Override
    public void init() throws ServletException {
        super.init();
        connectorProcessor = new ConnectorProcessor(getTPSEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findConnectors(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ConnectorServlet.findConnectors(): session: {}", session.getId());
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String filter = request.getParameter("filter");
        ConnectorCollection connectors = connectorProcessor.findConnectors(filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(connectors.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void addConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ConnectorServlet.addConnector(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ConnectorData data = JSONSerializer.fromJSON(requestData, ConnectorData.class);
        ConnectorData newConnector = connectorProcessor.addConnector(request.getUserPrincipal(), data);
        String encodedID = URLEncoder.encode(newConnector.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(newConnector.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ConnectorServlet.getConnector(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String connectorID = pathElement[0];
        ConnectorData connector = connectorProcessor.getConnector(connectorID);
        PrintWriter out = response.getWriter();
        out.println(connector.toJSON());

    }

    @WebAction(method = HttpMethod.PATCH, paths = {"{}"})
    public void updateConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ConnectorServlet.updateConnector(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String connectorID = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ConnectorData data = JSONSerializer.fromJSON(requestData, ConnectorData.class);
        ConnectorData connector = connectorProcessor.updateConnector(request.getUserPrincipal(), connectorID, data);
        PrintWriter out = response.getWriter();
        out.println(connector.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}"})
    public void changeStatus(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ConnectorServlet.changeStatus(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String connectorID = pathElement[0];
        String action = request.getParameter("action");
        ConnectorData connector = connectorProcessor.changeStatus(request.getUserPrincipal(), connectorID, action);
        PrintWriter out = response.getWriter();
        out.println(connector.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void removeConnector(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ConnectorServlet.removeConnector(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String connectorID = pathElement[0];
        connectorProcessor.removeConnector(request.getUserPrincipal(), connectorID);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
