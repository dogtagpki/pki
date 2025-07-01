//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.stream.Collectors;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.server.rest.base.UserServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.user.UserMembershipData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class UserServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(UserServlet.class);

    private UserServletBase userServletBase;

    @Override
    public void init() throws ServletException {
        super.init();
        userServletBase = new UserServletBase(getEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findUsers(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.findUsers(): session: {}", session.getId());
        String filter = request.getParameter("filter");
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        UserCollection users = userServletBase.findUsers(filter, start, size, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(users.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void addUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.addUser(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData user = userServletBase.addUser(userData, request.getLocale());
        String encodedUserID = URLEncoder.encode(user.getUserID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedUserID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(user.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.getUser(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        UserData user = userServletBase.getUser(userId, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(user.toJSON());

    }

    @WebAction(method = HttpMethod.PATCH, paths = {"{}"})
    public void modifyUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.modifyUser(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData user = userServletBase.modifyUser(userId, userData, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(user.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void removeUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.removeUser(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        userServletBase.removeUser(userId, request.getLocale());
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/certs"})
    public void findUserCerts(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.findUserCerts(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        UserCertCollection userCerts = userServletBase.findUserCerts(userId, start, size, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(userCerts.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/certs"})
    public void addUserCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.addUserCert(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        UserCertData userCertData = JSONSerializer.fromJSON(requestData, UserCertData.class);
        UserCertData userCert = userServletBase.addUserCert(userId, userCertData, request.getLocale());
        if (userCert == null) {
            return;
        }
        String encodedUserCertID = URLEncoder.encode(userCert.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedUserCertID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(userCertData.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/certs/{}"})
    public void getUserCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.getUserCert(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        String certId = pathElement[2];
        UserCertData userCert = userServletBase.getUserCert(userId, certId, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(userCert.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}/certs/{}"})
    public void removeUserCert(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.removeUserCert(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        String certId = pathElement[2];
        userServletBase.removeUserCert(userId, certId, request.getLocale());
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/memberships"})
    public void findUserMemberships(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.findUserMemberships(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        String filter = request.getParameter("filter");
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        UserMembershipCollection userMemberships = userServletBase.findUserMemberships(userId, filter, start, size, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(userMemberships.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/memberships"})
    public void addUserMembership(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.addUserMembership(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        String groupId = request.getReader().readLine();
        UserMembershipData userMembership = userServletBase.addUserMembership(userId, groupId, request.getLocale());
        String encodedUserGroupID = URLEncoder.encode(groupId, "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedUserGroupID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(userMembership.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}/memberships/{}"})
    public void removeUserMembership(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServlet.removeUserMembership(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        String groupId = pathElement[2];
        userServletBase.removeUserMembership(userId, groupId, request.getLocale());
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
