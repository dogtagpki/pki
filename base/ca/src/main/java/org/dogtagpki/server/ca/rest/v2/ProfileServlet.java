//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.server.ca.rest.base.ProfileBase;
import org.dogtagpki.server.rest.v2.PKIServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caProfile",
        urlPatterns = "/v2/profiles/*")
public class ProfileServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ProfileServlet.class);

    private ProfileBase profile;

    @Override
    public void init() throws ServletException {
        super.init();
        profile = new ProfileBase(engine);
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void listProfiles(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.listProfiles(): session: {}", session.getId());
        int size = request.getParameter("size") == null ?
                PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
        int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
        Boolean visible = request.getParameter("visible") == null ? null : Boolean.valueOf(request.getParameter("visible"));
        Boolean enable = request.getParameter("enable") == null ? null : Boolean.valueOf(request.getParameter("enable"));
        String enableBy = request.getParameter("enableBy");
        ProfileDataInfos profiles = profile.listProfiles(request, start, size, visible, enable,  enableBy);
        PrintWriter out = response.getWriter();
        out.println(profiles.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void retrieveProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.retrieveProfile(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileId = pathElement[0];
        ProfileData profileData = profile.retrieveProfile(request, profileId);
        PrintWriter out = response.getWriter();
        out.println(profileData.toJSON());

    }

    @WebAction(method = HttpMethod.GET, paths = {"{}/raw"})
    public void retrieveProfileRaw(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.retrieveProfileRaw(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileId = pathElement[0];
        byte[] rawProfile = profile.retrieveRawProfile(request, profileId);
        response.setContentType(MimeType.APPLICATION_OCTET_STREAM);
        OutputStream out = response.getOutputStream();
        out.write(rawProfile);
    }

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void createProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.createProfile(): session: {}", session.getId());
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ProfileData reqProfile = JSONSerializer.fromJSON(requestData, ProfileData.class);
        String newProfileId = profile.createProfile(request, reqProfile);
        ProfileData newProfile = profile.retrieveProfile(request, newProfileId);
        String encodedGroupID = URLEncoder.encode(newProfileId, "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedGroupID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        PrintWriter out = response.getWriter();
        out.println(newProfile.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"raw"})
    public void createProfileRaw(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.createProfileRaw(): session: {}", session.getId());
        InputStream input = request.getInputStream();
        byte[] data = input.readAllBytes();
        String newProfileId = profile.createProfile(data);
        String encodedGroupID = URLEncoder.encode(newProfileId, "UTF-8");
        StringBuffer uri = request.getRequestURL();
        uri.append("/" + encodedGroupID);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", uri.toString());
        byte[] rawProfile = profile.retrieveRawProfile(request, newProfileId);
        response.setContentType(MimeType.APPLICATION_OCTET_STREAM);
        OutputStream out = response.getOutputStream();
        out.write(rawProfile);
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}"})
    public void modifyProfileState(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.modifyProfileState(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileId = pathElement[0];
        String action = request.getParameter("action");
        profile.modifyProfileState(request.getUserPrincipal(), profileId, action);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    @WebAction(method = HttpMethod.PUT, paths = {"{}"})
    public void modifyProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.modifyProfile(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileId = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        ProfileData reqProfile = JSONSerializer.fromJSON(requestData, ProfileData.class);
        ProfileData newProfile = profile.modifyProfile(request, profileId, reqProfile);
        PrintWriter out = response.getWriter();
        out.println(newProfile.toJSON());
    }

    @WebAction(method = HttpMethod.PUT, paths = {"{}/raw"})
    public void modifyProfileRaw(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.modifyProfileRaw(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileId = pathElement[0];
        InputStream input = request.getInputStream();
        byte[] data = input.readAllBytes();
        byte[] newRawProfile = profile.modifyProfile(profileId, data);
        response.setContentType(MimeType.APPLICATION_OCTET_STREAM);
        OutputStream out = response.getOutputStream();
        out.write(newRawProfile);
    }

    @WebAction(method = HttpMethod.DELETE, paths = {"{}"})
    public void deleteProfile(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("ProfileServlet.deleteProfile(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String profileId = pathElement[0];
        profile.deleteProfile(profileId);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
