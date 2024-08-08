//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2;

import java.io.PrintWriter;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.kra.rest.base.KeyProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.MediaType;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.key.KeyInfo;
import com.netscape.certsrv.key.KeyInfoCollection;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "kraKey",
        urlPatterns = "/v2/agent/keys/*")
public class KeyServlet extends KRAServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(KeyServlet.class);

    KeyProcessor keyProcessor;

    @Override
    public void init() throws ServletException {
        super.init();
        keyProcessor = new KeyProcessor(engine);
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void listKeys(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyServlet.listKeys(): session: {}", session.getId());
        String clientKeyID = request.getParameter("clientKeyID");
        String status = request.getParameter("status");
        int maxResults = request.getParameter("maxResults") == null ?
                DEFAULT_MAXRESULTS : Integer.parseInt(request.getParameter("maxResults"));
        int maxTime = request.getParameter("maxTime") == null ?
                DEFAULT_MAXTIME : Integer.parseInt(request.getParameter("maxTime"));
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String realm = request.getParameter("realm");
        String owner = request.getParameter("owner");
        KeyInfoCollection keys = keyProcessor.listKeys(request.getUserPrincipal(), request.getRequestURL().toString(), clientKeyID, status, maxResults, maxTime, start, size, realm, owner);
        PrintWriter out = response.getWriter();
        out.println(keys.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getKeyInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyServlet.getKeyInfo(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        KeyId id = new KeyId(pathElement[0]);
        String baseUrl = request.getRequestURL().toString();
        baseUrl = baseUrl.substring(0, baseUrl.indexOf(request.getPathInfo()));
        KeyInfo info = keyProcessor.getKeyInfo(request.getUserPrincipal(), baseUrl, id);
        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"active/{}"})
    public void getActiveKeyInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyServlet.getActiveKeyInfo(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String clientKeyID = pathElement[1];
        String baseUrl = request.getRequestURL().toString();
        baseUrl = baseUrl.substring(0, baseUrl.indexOf(request.getPathInfo()));
        KeyInfo info = keyProcessor.getActiveKeyInfo(request.getUserPrincipal(), baseUrl, clientKeyID);
        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}"})
    public void modifyKeyStatus(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyServlet.modifyKeyStatus(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        KeyId id = new KeyId(pathElement[0]);
        String status = request.getParameter("status");
        String baseUrl = request.getRequestURL().toString();
        baseUrl = baseUrl.substring(0, baseUrl.indexOf(request.getPathInfo()));
        keyProcessor.modifyKeyStatus(request.getUserPrincipal(), baseUrl, id, status);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.POST, paths = {"retrieve"})
    public void retrieveKey(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("KeyServlet.retrieveKey(): session: {}", session.getId());
        KeyRecoveryRequest data = null;
        if(request.getContentType() == null || request.getContentType().equals(MediaType.APPLICATION_JSON)) {
            String requestData = request.getReader().lines().collect(Collectors.joining());
            data = JSONSerializer.fromJSON(requestData, KeyRecoveryRequest.class);
        }
        if(request.getContentType().equals(MediaType.APPLICATION_FORM_URLENCODED)) {
            data = new KeyRecoveryRequest(request.getParameterMap());
        }
        if(data == null) {
            response.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
            return;
        }
        KeyData keyData = keyProcessor.retrieveKey(request.getUserPrincipal() , data);
        PrintWriter out = response.getWriter();
        out.println(keyData.toJSON());
    }
}
