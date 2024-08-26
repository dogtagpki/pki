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

import org.dogtagpki.server.tps.rest.base.ProfileMappingProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.tps.profile.ProfileMappingCollection;
import com.netscape.certsrv.tps.profile.ProfileMappingData;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsProfileMapping",
        urlPatterns = "/v2/profile-mappings/*")
public class ProfileMappingServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(ProfileMappingServlet.class);

    private ProfileMappingProcessor profileMappingProcessor;

    @Override
    public void init() throws ServletException {
        super.init();
        profileMappingProcessor = new ProfileMappingProcessor(getTPSEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void findProfileMappings(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileMappingServlet.findProfileMappings(): session: {}", session.getId());
        int size = request.getParameter("pageSize") == null ?
                DEFAULT_SIZE : Integer.parseInt(request.getParameter("pageSize"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        String filter = request.getParameter("filter");
        ProfileMappingCollection profileMappings = profileMappingProcessor.findProfileMappings(filter, start, size);
        PrintWriter out = response.getWriter();
        out.println(profileMappings.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void addProfileMapping(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileMappingServlet.addProfileMapping(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ProfileMappingData profileMappingData = JSONSerializer.fromJSON(requestData, ProfileMappingData.class);
        ProfileMappingData newProfileMapping = profileMappingProcessor.addProfileMapping(request.getUserPrincipal(), profileMappingData);
        String encodedID = URLEncoder.encode(newProfileMapping.getID(), "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedID);
        response.setHeader("Location", uri.toString());
        response.setStatus(HttpServletResponse.SC_CREATED);
        PrintWriter out = response.getWriter();
        out.println(newProfileMapping.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getProfileMapping(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileMappingServlet.getProfileMapping(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileMappingID = pathElement[0];
        ProfileMappingData profileMapping = profileMappingProcessor.getProfileMapping(profileMappingID);
        PrintWriter out = response.getWriter();
        out.println(profileMapping.toJSON());
    }

    @WebAction(method = HttpMethod.PATCH, paths = {"{}"})
    public void updateProfileMapping(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileMappingServlet.updateProfileMapping(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileMappingID = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ProfileMappingData profileMappingData = JSONSerializer.fromJSON(requestData, ProfileMappingData.class);
        ProfileMappingData profileMapping = profileMappingProcessor.updateProfileMapping(request.getUserPrincipal(), profileMappingID, profileMappingData);
        PrintWriter out = response.getWriter();
        out.println(profileMapping.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}"})
    public void changeStatus(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileMappingServlet.changeStatus(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileMappingID = pathElement[0];
        String action = request.getParameter("action");
        ProfileMappingData profileMapping = profileMappingProcessor.changeStatus(request.getUserPrincipal(), profileMappingID, action);
        PrintWriter out = response.getWriter();
        out.println(profileMapping.toJSON());
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void removeProfileMapping(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileMappingServlet.removeProfileMapping(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileMappingID = pathElement[0];
        profileMappingProcessor.removeProfileMapping(request.getUserPrincipal(), profileMappingID);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
