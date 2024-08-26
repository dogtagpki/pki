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

import org.dogtagpki.server.tps.rest.base.ProfileProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.tps.profile.ProfileCollection;
import com.netscape.certsrv.tps.profile.ProfileData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsProfile",
        urlPatterns = "/v2/profiles/*")
public class TPSProfileServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(TPSProfileServlet.class);

    private ProfileProcessor profileProcessor;

    @Override
    public void init() throws ServletException {
        super.init();
        profileProcessor = new ProfileProcessor(getTPSEngine());
    }
    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findProfiles(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSProfileServlet.findProfiles(): session: {}", session.getId());
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String filter = request.getParameter("filter");
        ProfileCollection profiles = profileProcessor.findProfiles(getAuthorizedProfiles(request), filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(profiles.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void addProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSProfileServlet.addProfile(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ProfileData profileData = JSONSerializer.fromJSON(requestData, ProfileData.class);
        ProfileData newProfile = profileProcessor.addProfile(request.getUserPrincipal(), profileData);
        String encodedID = URLEncoder.encode(newProfile.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedID);
        response.setHeader("Location", uri.toString());
        response.setStatus(HttpServletResponse.SC_CREATED);
        PrintWriter out = response.getWriter();
        out.println(newProfile.toJSON());

    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSProfileServlet.getProfile(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileID = pathElement[0];
        ProfileData profile = profileProcessor.getProfile(getAuthorizedProfiles(request), profileID);
        PrintWriter out = response.getWriter();
        out.println(profile.toJSON());
    }

    @WebAction(method = HttpMethod.PATCH, paths = {"{}"})
    public void updateProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSProfileServlet.updateProfile(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileID = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ProfileData profileData = JSONSerializer.fromJSON(requestData, ProfileData.class);
        ProfileData newProfile = profileProcessor.updateProfile(request.getUserPrincipal(), getAuthorizedProfiles(request), profileID, profileData);
        PrintWriter out = response.getWriter();
        out.println(newProfile.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}"})
    public void changeStatus(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSProfileServlet.changeStatus(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileID = pathElement[0];
        String action = request.getParameter("action");
        ProfileData newProfile = profileProcessor.changeStatus(request.getUserPrincipal(), getAuthorizedProfiles(request), profileID, action);
        PrintWriter out = response.getWriter();
        out.println(newProfile.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void removeProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("TPSProfileServlet.removeProfile(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileID = pathElement[0];
        profileProcessor.removeProfile(request.getUserPrincipal(), profileID);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
