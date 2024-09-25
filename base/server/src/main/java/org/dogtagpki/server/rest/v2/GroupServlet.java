//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.rest.base.GroupServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.group.GroupCollection;
import com.netscape.certsrv.group.GroupData;
import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class GroupServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(GroupServlet.class);

    private GroupServletBase groupServletBase;

    @Override
    public void init() throws ServletException {
        super.init();
        groupServletBase = new GroupServletBase(getEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findGroups(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.findGroups(): session: {}", session.getId());
        String filter = request.getParameter("filter");
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        GroupCollection groups = groupServletBase.findGroups(filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(groups.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void addGroup(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.addGroup(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        GroupData groupData = JSONSerializer.fromJSON(requestData, GroupData.class);
        GroupData group = groupServletBase.addGroup(groupData, request.getLocale());
        String encodedGroupID = URLEncoder.encode(group.getGroupID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedGroupID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(group.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getGroup(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.getGroup(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String groupId = pathElement[0];
        GroupData group = groupServletBase.getGroup(groupId, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(group.toJSON());
    }

    @WebAction(method = HttpMethod.PATCH, paths = {"{}"})
    public void modifyGroup(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.modifyGroup(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String groupId = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        GroupData groupData = JSONSerializer.fromJSON(requestData, GroupData.class);
        GroupData group = groupServletBase.modifyGroup(groupId, groupData, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(group.toJSON());

    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void removeGroup(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.removeGroup(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String groupId = pathElement[0];
        groupServletBase.removeGroup(groupId, request.getLocale());
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/members"})
    public void findGroupMembers(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.findGroupMembers(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String groupId = pathElement[0];
        String filter = request.getParameter("filter");
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        GroupMemberCollection groupMembers = groupServletBase.findGroupMembers(groupId, filter, start, size, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(groupMembers.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/members"})
    public void addGroupMember(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.addGroupMember(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String groupId = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        GroupMemberData groupMemberData = JSONSerializer.fromJSON(requestData, GroupMemberData.class);
        GroupMemberData groupMember = groupServletBase.addGroupMember(groupId, groupMemberData, request.getLocale());
        String encodedGroupMemberID = URLEncoder.encode(groupMember.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedGroupMemberID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(groupMember.toJSON());

    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/members/{}"})
    public void getGroupMember(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.getGroupMember(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String groupId = pathElement[0];
        String memberId = pathElement[2];
        GroupMemberData groupMember = groupServletBase.getGroupMember(groupId, memberId, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(groupMember.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}/members/{}"})
    public void removeGroupMember(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("GroupServletBase.removeGroupMember(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String groupId = pathElement[0];
        String memberId = pathElement[2];
        groupServletBase.removeGroupMember(groupId, memberId, request.getLocale());
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
