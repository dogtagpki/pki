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

import org.dogtagpki.server.tps.rest.base.AuthenticatorProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.tps.authenticator.AuthenticatorCollection;
import com.netscape.certsrv.tps.authenticator.AuthenticatorData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsAuthenticator",
        urlPatterns = "/v2/authenticators/*")
public class AuthenticatorServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticatorServlet.class);

    private AuthenticatorProcessor authenticatorProcessor;
    @Override
    public void init() throws ServletException {
        super.init();
        authenticatorProcessor = new AuthenticatorProcessor(getTPSEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findAuthenticators(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuthenticatorServlet.findAuthenticators(): session: {}", session.getId());
        String filter = request.getParameter("filter");
        int size = request.getParameter("size") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));

        AuthenticatorCollection authenticators = authenticatorProcessor.findAuthenticators(filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(authenticators.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void addAuthenticator(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuthenticatorServlet.addAuthenticator(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        AuthenticatorData authenticatorData = JSONSerializer.fromJSON(requestData, AuthenticatorData.class);
        AuthenticatorData newAuthenticator = authenticatorProcessor.addAuthenticator(request.getUserPrincipal(), authenticatorData);
        String encodedID = URLEncoder.encode(newAuthenticator.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(newAuthenticator.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getAuthenticator(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuthenticatorServlet.getAuthenticator(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String authenticatorID = pathElement[0];
        AuthenticatorData authenticator = authenticatorProcessor.getAuthenticator(authenticatorID);
        PrintWriter out = response.getWriter();
        out.println(authenticator.toJSON());
    }

    @WebAction(method = HttpMethod.PATCH, paths = {"{}"})
    public void updateAuthenticator(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuthenticatorServlet.updateAuthenticator(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String authenticatorID = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        AuthenticatorData authenticatorData = JSONSerializer.fromJSON(requestData, AuthenticatorData.class);
        AuthenticatorData newAuthenticator = authenticatorProcessor.updateAuthenticator(request.getUserPrincipal(), authenticatorID, authenticatorData);
        PrintWriter out = response.getWriter();
        out.println(newAuthenticator.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}"})
    public void changeStatus(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuthenticatorServlet.changeStatus(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String authenticatorID = pathElement[0];
        String action = request.getParameter("action");
        AuthenticatorData newAuthenticator = authenticatorProcessor.changeStatus(request.getUserPrincipal(), authenticatorID, action);
        PrintWriter out = response.getWriter();
        out.println(newAuthenticator.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void removeAuthenticator(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("AuthenticatorServlet.addAuthenticator(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String authenticatorID = pathElement[0];
        authenticatorProcessor.removeAuthenticator(request.getUserPrincipal(), authenticatorID);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
