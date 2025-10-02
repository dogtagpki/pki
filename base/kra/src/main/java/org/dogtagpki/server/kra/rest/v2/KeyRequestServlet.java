//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.stream.Collectors;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.server.kra.rest.base.KeyRequestProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfoCollection;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "kraKeyRequest",
        urlPatterns = "/v2/agent/keyrequests/*")
public class KeyRequestServlet extends KRAServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(KeyRequestServlet.class);

    private KeyRequestProcessor keyReqProcessor;

    @Override
    public void init() throws ServletException {
        super.init();
        keyReqProcessor = new KeyRequestProcessor(engine);
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void listRequests(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyRequestServlet.listRequests(): session: {}", session.getId());
        String requestState = request.getParameter("requestState");
        String requestType = request.getParameter("requestType");
        String clientKeyID = request.getParameter("clientKeyID");
        int maxTime = request.getParameter("maxTime") == null ?
                DEFAULT_MAXTIME : Integer.parseInt(request.getParameter("maxTime"));
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String realm = request.getParameter("realm");
        KeyRequestInfoCollection keyRequests = keyReqProcessor.listRequests(
                request.getUserPrincipal(), request.getRequestURL().toString(),
                requestState, requestType, clientKeyID, maxTime, start, size, realm);
        PrintWriter out = response.getWriter();
        out.println(keyRequests.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getRequestInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyRequestServlet.getRequestInfo(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        RequestId id = new RequestId(pathElement[0]);
        String baseUrl = request.getRequestURL().toString();
        baseUrl = baseUrl.substring(0, baseUrl.indexOf(request.getPathInfo()));
        KeyRequestInfo keyRequest = keyReqProcessor.getRequestInfo(request.getUserPrincipal(), baseUrl, id);
        PrintWriter out = response.getWriter();
        out.println(keyRequest.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void submitRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyRequestServlet.submitRequest(): session: {}", session.getId());
        RESTMessage data = null;
        if(request.getContentType() == null || request.getContentType().equals(MimeType.APPLICATION_JSON)) {
            String requestData = request.getReader().lines().collect(Collectors.joining());
            data = JSONSerializer.fromJSON(requestData, RESTMessage.class);
        }
        if(request.getContentType().equals(MimeType.APPLICATION_FORM_URLENCODED)) {
            data = new RESTMessage(request.getParameterMap());
        }
        if(data == null) {
            response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
            return;
        }
        KeyRequestResponse keyRequest = keyReqProcessor.submitRequest(request.getUserPrincipal(), request.getRequestURL().toString(), data);
        response.setStatus(HttpServletResponse.SC_CREATED);
        String encodedID = URLEncoder.encode(keyRequest.getRequestId().toHexString(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedID);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(keyRequest.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/approve", "{}/reject", "{}/cancel"})
    public void modifyRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyRequestServlet.modifyRequest(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        RequestId id;
        try {
            id = new RequestId(pathElement[0]);
        } catch(NumberFormatException e) {
            throw new BadRequestException("Id not valid: " + pathElement[0]);
        }
        String operation = pathElement[1];
        if(operation.equals("approve")) {
            keyReqProcessor.approve(request.getUserPrincipal(), id);
        }
        if(operation.equals("reject")) {
            keyReqProcessor.reject(request.getUserPrincipal(), id);
        }
        if(operation.equals("cancel")) {
            keyReqProcessor.cancel(request.getUserPrincipal(), id);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
