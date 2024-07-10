//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.InternalCertificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.pkcs11.PK11Cert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UserNotFoundException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.user.UserMembershipData;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.password.PasswordChecker;
import com.netscape.cms.servlet.admin.GroupMemberProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class UserServletBase {
    public static final Logger logger = LoggerFactory.getLogger(UserServletBase.class);

    public static final String ATTR_TPS_PROFILES = "tpsProfiles";
    public static final String ALL_PROFILES = "All Profiles";
    public static final String BACK_SLASH = "\\";
    public static final String SYSTEM_USER = "$System$";

    private CMSEngine engine;

    public UserServletBase(CMSEngine engine) {
        this.engine = engine;
    }
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServletBase.get(): session: {}", session.getId());

        PrintWriter out = response.getWriter();
        if (request.getPathInfo() == null) {
            String filter = request.getParameter("filter");
            int size = request.getParameter("size") == null ?
                    PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
            int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
            UserCollection users = findUsers(filter, start, size, request.getLocale());
            out.println(users.toJSON());
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        if (pathElement.length == 1) {
            UserData user = getUser(userId, request.getLocale());
            out.println(user.toJSON());
            return;
        }
        if(pathElement[1].equals("certs")) {
            if (pathElement.length == 2) {
                int size = request.getParameter("size") == null ?
                        PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
                int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
                UserCertCollection userCerts = findUserCerts(userId, start, size, request.getLocale());
                out.println(userCerts.toJSON());
                return;
            }
            if (pathElement.length == 3) {
                String certId = pathElement[2];
                UserCertData userCert = getUserCert(userId, certId, request.getLocale());
                out.println(userCert.toJSON());
                return;
            }
        }
        if (pathElement[1].equals("memberships") && pathElement.length == 2) {
            String filter = request.getParameter("filter");
            int size = request.getParameter("size") == null ?
                    PKIServlet.DEFAULT_SIZE : Integer.parseInt(request.getParameter("size"));
            int start = request.getParameter("start") == null ? 0 : Integer.parseInt(request.getParameter("start"));
            UserMembershipCollection userMemberships = findUserMemberships(userId, filter, start, size, request.getLocale());
            out.println(userMemberships.toJSON());
            return;
        }
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServletBase.get(): session: {}", session.getId());
        String contentType = request.getContentType();
        if (Objects.nonNull(contentType) && !contentType.equals("application/json")) {
            throw new BadRequestDataException(contentType + " not accepted");
        }
        PrintWriter out = response.getWriter();
        if (request.getPathInfo() == null) {
            String requestData = request.getReader().lines().collect(Collectors.joining());
            UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
            UserData user = addUser(userData, request.getLocale());
            String encodedUserID = URLEncoder.encode(user.getUserID(), "UTF-8");
            StringBuffer uri = request.getRequestURL();
            uri.append("/" + encodedUserID);
            response.setStatus(HttpServletResponse.SC_CREATED);
            response.setHeader("Location", uri.toString());
            out.println(user.toJSON());
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        if (pathElement.length == 2) {
            if (pathElement[1].equals("certs")) {
                String requestData = request.getReader().lines().collect(Collectors.joining());
                UserCertData userCertData = JSONSerializer.fromJSON(requestData, UserCertData.class);
                UserCertData userCert = addUserCert(userId, userCertData, request.getLocale());
                if (userCert == null) {
                    return;
                }
                String encodedUserCertID = URLEncoder.encode(userCert.getID(), "UTF-8");
                StringBuffer uri = request.getRequestURL();
                uri.append("/" + encodedUserCertID);
                response.setStatus(HttpServletResponse.SC_CREATED);
                response.setHeader("Location", uri.toString());
                out.println(userCertData.toJSON());
                return;
            }
            if (pathElement[1].equals("memberships")) {
                String groupId = request.getReader().readLine();
                UserMembershipData userMembership = addUserMembership(userId, groupId, request.getLocale());
                String encodedUserGroupID = URLEncoder.encode(groupId, "UTF-8");
                StringBuffer uri = request.getRequestURL();
                uri.append("/" + encodedUserGroupID);
                response.setStatus(HttpServletResponse.SC_CREATED);
                response.setHeader("Location", uri.toString());
                out.println(userMembership.toJSON());
                return;
            }
        }
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    public void patch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServletBase.get(): session: {}", session.getId());
        if (request.getPathInfo() == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        if (pathElement.length > 1) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        String userId = pathElement[0];
        String requestData = request.getReader().lines().collect(Collectors.joining());
        UserData userData = JSONSerializer.fromJSON(requestData, UserData.class);
        UserData user = modifyUser(userId, userData, request.getLocale());
        PrintWriter out = response.getWriter();
        out.println(user.toJSON());
    }

    public void delete(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("UserServletBase.get(): session: {}", session.getId());
        if (request.getPathInfo() == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String userId = pathElement[0];
        if (pathElement.length == 1) {
            removeUser(userId, request.getLocale());
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            return;
        }
        if (pathElement.length == 3) {
            if (pathElement[1].equals("certs")) {
                String certId = pathElement[2];
                removeUserCert(userId, certId, request.getLocale());
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                return;
            }
            if (pathElement[1].equals("memberships")) {
                String groupId = pathElement[2];
                removeUserMembership(userId, groupId, request.getLocale());
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
                return;
            }
        }
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    private UserCollection findUsers(String filter, int start, int size, Locale loc) {

        if (filter != null && filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        UserCollection response = new UserCollection();

        try {
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            Enumeration<User> users = userGroupManager.findUsersByKeyword(filter);

            int i = 0;

            // skip to the start of the page
            for ( ; i<start && users.hasMoreElements(); i++) users.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && users.hasMoreElements(); i++) {
                User user = users.nextElement();
                response.addEntry(createUserData(user));
            }

            // count the total entries
            for ( ; users.hasMoreElements(); i++) users.nextElement();
            response.setTotal(i);

            return response;

        } catch (EUsrGrpException e) {
            // Workaround for ticket #914.
            // If no users found, return empty result.
            if (CMS.getUserMessage(loc, "CMS_USRGRP_USER_NOT_FOUND").equals(e.getMessage())) {
                logger.debug("UserServletBase.findUsers(): {}", e.getMessage());
                return response;
            }

            logger.error("UserServletBase: " + e.getMessage(), e);
            throw new PKIException(e);

        } catch (Exception e) {
            logger.error("UserServletBase: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public UserData getUser(String userID, Locale loc) {
        try {
            if (userID == null || userID.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(CMS.getUserMessage(loc, "CMS_INTERNAL_ERROR"));
            }

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            UserData userData = createUserData(user);

            String email = user.getEmail();
            if (!StringUtils.isEmpty(email)) userData.setEmail(email);

            String phone = user.getPhone();
            if (!StringUtils.isEmpty(phone)) userData.setPhone(phone);

            String state = user.getState();
            if (!StringUtils.isEmpty(state)) userData.setState(state);

            String type = user.getUserType();
            if (!StringUtils.isEmpty(type)) userData.setType(type);

            // TODO: refactor into TPSUserService
            String csType = engine.getName();
            if (csType.equals("TPS")) {

                List<String> profiles = user.getTpsProfiles();
                if (profiles != null) {
                    StringBuilder sb = new StringBuilder();
                    String prefix = "";
                    for (String profile: profiles) {
                        sb.append(prefix);
                        prefix = ",";
                        sb.append(profile);
                    }

                    userData.setAttribute(ATTR_TPS_PROFILES, sb.toString());
                }
            }
            return userData;
        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    private UserData createUserData(User user) throws Exception {

        UserData userData = new UserData();

        String userID = user.getUserID();
        if (!StringUtils.isEmpty(userID)) {
            userData.setID(userID);
            userData.setUserID(userID);
        }

        String fullName = user.getFullName();
        if (!StringUtils.isEmpty(fullName)) userData.setFullName(fullName);

        return userData;
    }

    private UserCertCollection findUserCerts(String userID, int start, int size, Locale loc) {
        try {
            if (userID == null || userID.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(CMS.getUserMessage(loc, "CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
            }

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            X509Certificate[] certs = user.getX509Certificates();
            if (certs == null) certs = new X509Certificate[0];
            Iterator<X509Certificate> entries = Arrays.asList(certs).iterator();

            UserCertCollection userCerts = new UserCertCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && entries.hasNext(); i++) entries.next();

            // return entries up to the page size
            for ( ; i<start+size && entries.hasNext(); i++) {
                userCerts.addEntry(createUserCertData(userID, entries.next()));
            }

            // count the total entries
            for ( ; entries.hasNext(); i++) entries.next();
            userCerts.setTotal(i);

            return userCerts;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    private UserCertData createUserCertData(String userID, X509Certificate cert) throws Exception {

        UserCertData userCertData = new UserCertData();

        userCertData.setVersion(cert.getVersion());
        userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
        userCertData.setIssuerDN(cert.getIssuerDN().toString());
        userCertData.setSubjectDN(cert.getSubjectDN().toString());
        return userCertData;
    }

    public UserCertData getUserCert(String userID, String certID, Locale loc) {

        if (certID == null) throw new BadRequestException("Certificate ID is null.");

        try {
            if (userID == null || userID.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(CMS.getUserMessage(loc, "CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
            }

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            X509Certificate[] certs = user.getX509Certificates();

            if (certs == null) {
                throw new ResourceNotFoundException("No certificates found for " + userID);
            }

            try {
                certID = URLDecoder.decode(certID, "UTF-8");
            } catch (Exception e) {
                throw new PKIException(e.getMessage());
            }

            for (X509Certificate cert : certs) {

                UserCertData userCertData = createUserCertData(userID, cert);

                if (!userCertData.getID().equals(certID)) continue;

                CertPrettyPrint print = new CertPrettyPrint(cert);
                userCertData.setPrettyPrint(print.toString(loc));

                // add base64 encoding
                String base64 = CertUtil.toPEM(cert);
                userCertData.setEncoded(base64);

                return userCertData;
            }

            throw new ResourceNotFoundException("No certificates found for " + userID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    private UserMembershipCollection findUserMemberships(String userID, String filter, int start, int size, Locale loc) {

        logger.debug("UserServletBase.findUserMemberships(" + userID + ", " + filter + ")");

        if (userID == null || userID.isBlank()) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
            throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
        }

        if (filter != null && filter.length() < 3) {
            throw new BadRequestException("Filter is too short.");
        }
        try {
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.getUser(userID);

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            Enumeration<Group> groups = userGroupManager.findGroupsByUser(user.getUserDN(), filter);

            UserMembershipCollection userMemberships = new UserMembershipCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && groups.hasMoreElements(); i++) groups.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && groups.hasMoreElements(); i++) {
                Group group = groups.nextElement();
                userMemberships.addEntry(createUserMembershipData(userID, group.getName()));
            }

            // count the total entries
            for ( ; groups.hasMoreElements(); i++) groups.nextElement();
            userMemberships.setTotal(i);

            return userMemberships;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    private UserMembershipData createUserMembershipData(String userID, String groupID) {

        UserMembershipData userMembershipData = new UserMembershipData();
        userMembershipData.setID(groupID);
        userMembershipData.setUserID(userID);

        return userMembershipData;
    }

    private UserData addUser(UserData userData, Locale loc) {

        logger.debug("UserServletBase.addUser()");

        if (userData == null) throw new BadRequestException("User data is null.");

        String userID = userData.getUserID();
        logger.debug("User ID: {}", userID);

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null || userID.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            if (userID.indexOf(BACK_SLASH) != -1) {
                // backslashes (BS) are not allowed
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_RS_ID_BS"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_RS_ID_BS"));
            }

            if (userID.equals(SYSTEM_USER)) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_SPECIAL_ID", userID));
                throw new ForbiddenException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_SPECIAL_ID", userID));
            }

            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.createUser(userID);

            String fname = userData.getFullName();
            logger.debug("Full name: {}", fname);

            if (fname == null || fname.length() == 0) {
                String msg = CMS.getUserMessage(loc, "CMS_USRGRP_USER_ADD_FAILED_1", "full name");
                logger.error(msg);
                throw new BadRequestException(msg);
            }
            user.setFullName(fname);

            String email = userData.getEmail();
            logger.debug("Email: {}", email);

            if (email != null) {
                user.setEmail(email);
            } else {
                user.setEmail("");
            }

            String pword = userData.getPassword();
            logger.debug("Password: {}", (pword == null ? null : "********"));

            if (pword != null && !pword.equals("")) {
                PasswordChecker passwdCheck = engine.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    throw new EUsrGrpException(passwdCheck.getReason(pword));
                }

                user.setPassword(pword);
            } else {
                user.setPassword("");
            }

            String phone = userData.getPhone();
            logger.debug("Phone: {}", phone);

            if (phone != null) {
                user.setPhone(phone);
            } else {
                user.setPhone("");
            }

            String type = userData.getType();
            logger.debug("Type: {}", type);

            if (type != null) {
                user.setUserType(type);
            } else {
                user.setUserType("");
            }

            String state = userData.getState();
            logger.debug("State: {}", state);

            if (state != null) {
                user.setState(state);
            }

            // TODO: refactor into TPSUserService
            String csType = engine.getName();
            if (csType.equals("TPS")) {

                String tpsProfiles = userData.getAttribute(ATTR_TPS_PROFILES);
                logger.debug("TPS profiles: {}", tpsProfiles);
                if (tpsProfiles != null) { // update profiles if specified

                    String[] profiles;
                    if (StringUtils.isEmpty(tpsProfiles)) {
                        profiles = new String[0];
                    } else {
                        profiles = tpsProfiles.split(",");
                    }

                    user.setTpsProfiles(Arrays.asList(profiles));
                }
            }

            userGroupManager.addUser(user);

            auditAddUser(userID, userData, ILogger.SUCCESS);

            // read the data back
            return getUser(userID, loc);


        } catch (PKIException e) {
            auditAddUser(userID, userData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditAddUser(userID, userData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    private UserData modifyUser(String userID, UserData userData, Locale loc) {

        logger.debug("UserServletBase.modifyUser({})", userID);

        if (userData == null) throw new BadRequestException("User data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null || userID.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.createUser(userID);

            String fullName = userData.getFullName();
            logger.debug("Full name: {}", fullName);
            if (fullName != null) {
                user.setFullName(fullName);
            }

            String email = userData.getEmail();
            logger.debug("Email: {}", email);
            if (email != null) {
                user.setEmail(email);
            }

            String pword = userData.getPassword();
            if (pword != null && !pword.equals("")) {
                PasswordChecker passwdCheck = engine.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    throw new EUsrGrpException(passwdCheck.getReason(pword));
                }

                user.setPassword(pword);
            }

            String phone = userData.getPhone();
            logger.debug("Phone: {}", phone);
            if (phone != null) {
                user.setPhone(phone);
            }

            String state = userData.getState();
            logger.debug("State: {}", state);
            if (state != null) {
                user.setState(state);
            }

            // TODO: refactor into TPSUserService
            String csType = engine.getName();
            if (csType.equals("TPS")) {
                String tpsProfiles = userData.getAttribute(ATTR_TPS_PROFILES);
                logger.debug("TPS Profiles: {}", tpsProfiles);
                if (tpsProfiles != null) { // update profiles if specified
                    String[] profiles;
                    if (StringUtils.isEmpty(tpsProfiles)) {
                        profiles = new String[0];
                    } else {
                        profiles = tpsProfiles.split(",");
                    }
                    user.setTpsProfiles(Arrays.asList(profiles));
                }
            }
            userGroupManager.modifyUser(user);
            auditModifyUser(userID, userData, ILogger.SUCCESS);

            // read the data back
            return getUser(userID, loc);

        } catch (PKIException e) {
            auditModifyUser(userID, userData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditModifyUser(userID, userData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    private void removeUser(String userID, Locale loc) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null || userID.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            // get list of groups, and see if uid belongs to any
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            Enumeration<Group> groups = userGroupManager.findGroups("*");

            while (groups.hasMoreElements()) {
                Group group = groups.nextElement();
                if (!group.isMember(userID)) continue;

                userGroupManager.removeUserFromGroup(group, userID);
            }

            // comes out clean of group membership...now remove user
            userGroupManager.removeUser(userID);

            auditDeleteUser(userID, ILogger.SUCCESS);
        } catch (PKIException e) {
            auditDeleteUser(userID, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditDeleteUser(userID, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    private UserCertData addUserCert(String userID, UserCertData userCertData, Locale loc) {

        if (userCertData == null) throw new BadRequestException("Certificate data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null || userID.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.createUser(userID);

            String encoded = userCertData.getEncoded();

            // no cert is a success
            if (encoded == null) {
                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);
                return null;
            }

            // only one cert added per operation
            X509Certificate cert = null;

            // Base64 decode cert
            byte[] binaryCert = Cert.parseCertificate(encoded);

            try {
                cert = new X509CertImpl(binaryCert);

            } catch (CertificateException e) {
                logger.warn("UserServletBase: Submitted data is not an X.509 certificate: " + e.getMessage(), e);
                // ignore
            }

            if (cert == null) {
                // TODO: Remove this code. Importing PKCS #7 is not supported.

                // cert chain direction
                boolean assending = true;

                // could it be a pkcs7 blob?
                logger.debug("UserServletBase: " + CMS.getLogMessage("ADMIN_SRVLT_IS_PK_BLOB"));

                try {
                    CryptoManager manager = CryptoManager.getInstance();

                    PKCS7 pkcs7 = new PKCS7(binaryCert);

                    X509Certificate[] p7certs = pkcs7.getCertificates();

                    if (p7certs.length == 0) {
                        logger.error("UserServletBase: PKCS #7 data contains no certificates");
                        throw new BadRequestException("PKCS #7 data contains no certificates");
                    }

                    // fix for 370099 - cert ordering can not be assumed
                    // find out the ordering ...

                    // self-signed and alone? take it. otherwise test
                    // the ordering
                    if (p7certs[0].getSubjectDN().toString().equals(
                            p7certs[0].getIssuerDN().toString()) &&
                            (p7certs.length == 1)) {
                        cert = p7certs[0];
                        logger.debug("UserServletBase: {}", CMS.getLogMessage("ADMIN_SRVLT_SINGLE_CERT_IMPORT"));

                    } else if (p7certs[0].getIssuerDN().toString().equals(p7certs[1].getSubjectDN().toString())) {
                        cert = p7certs[0];
                        logger.debug("UserServletBase: {}", CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_ACEND_ORD"));

                    } else if (p7certs[1].getIssuerDN().toString().equals(p7certs[0].getSubjectDN().toString())) {
                        assending = false;
                        logger.debug("UserServletBase: {}", CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_DESC_ORD"));
                        cert = p7certs[p7certs.length - 1];

                    } else {
                        // not a chain, or in random order
                        logger.error("UserServletBase: {}", CMS.getLogMessage("ADMIN_SRVLT_CERT_BAD_CHAIN"));
                        throw new BadRequestException(CMS.getUserMessage(loc, "CMS_USRGRP_SRVLT_CERT_ERROR"));
                    }

                    logger.debug("UserServletBase: {}",
                            CMS.getLogMessage("ADMIN_SRVLT_CHAIN_STORED_DB", String.valueOf(p7certs.length)));

                    int j = 0;
                    int jBegin = 0;
                    int jEnd = 0;

                    if (assending) {
                        jBegin = 1;
                        jEnd = p7certs.length;
                    } else {
                        jBegin = 0;
                        jEnd = p7certs.length - 1;
                    }

                    // store the chain into cert db, except for the user cert
                    for (j = jBegin; j < jEnd; j++) {
                        logger.debug("UserServletBase: {}",
                                CMS.getLogMessage("ADMIN_SRVLT_CERT_IN_CHAIN", String.valueOf(j),
                                        String.valueOf(p7certs[j].getSubjectDN())));
                        org.mozilla.jss.crypto.X509Certificate leafCert =
                                manager.importCACertPackage(p7certs[j].getEncoded());

                        if (leafCert == null) {
                            logger.warn("UserServletBase: missing leaf certificate");
                            logger.error(CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NULL"));
                        } else {
                            logger.debug("UserServletBase: {}", CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NON_NULL"));
                        }

                        if (leafCert instanceof InternalCertificate internalCert) {
                            internalCert.setSSLTrust(
                                    PK11Cert.VALID_CA |
                                    PK11Cert.TRUSTED_CA |
                                    PK11Cert.TRUSTED_CLIENT_CA);
                        } else {
                            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NOT_INTERNAL_CERT",
                                    String.valueOf(p7certs[j].getSubjectDN())));
                        }
                    }

                    /*
                    } catch (CryptoManager.UserCertConflictException e) {
                        // got a "user cert" in the chain, most likely the CA
                        // cert of this instance, which has a private key.  Ignore
                        logger.error(CMS.getLogMessage("ADMIN_SRVLT_PKS7_IGNORED", e.toString()));
                    */
                } catch (PKIException e) {
                    logger.error("UserServletBase: Unable to import user certificate from PKCS #7 data: {}", e.getMessage());
                    logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", e.toString()));
                    throw e;

                } catch (Exception e) {
                    logger.error("UserServletBase: " + e.getMessage(), e);
                    logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", e.toString()));
                    throw new PKIException("Unable to import user certificate from PKCS #7 data: " + e.getMessage(), e);
                }
            }

            try {
                logger.debug("UserServletBase: {}", CMS.getLogMessage("ADMIN_SRVLT_BEFORE_VALIDITY"));
                cert.checkValidity(); // throw exception if fails

                user.setX509Certificates(new X509Certificate[] { cert });
                userGroupManager.addUserCert(userID, cert);

                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);

                // read the data back

                userCertData.setVersion(cert.getVersion());
                userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
                userCertData.setIssuerDN(cert.getIssuerDN().toString());
                userCertData.setSubjectDN(cert.getSubjectDN().toString());
                String certID = userCertData.getID();

                return getUserCert(userID, certID, loc);

            } catch (CertificateExpiredException e) {
                logger.error("UserServletBase: Certificate expired: " + e.getMessage(), e);
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_ADD_CERT_EXPIRED",
                        String.valueOf(cert.getSubjectDN())));
                throw new BadRequestException("Certificate expired: " + e.getMessage(), e);

            } catch (CertificateNotYetValidException e) {
                logger.error("UserServletBase: Certificate not yet valid: " + e.getMessage(), e);
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_NOT_YET_VALID",
                        String.valueOf(cert.getSubjectDN())));
                throw new BadRequestException("Certificate not yet valid: " + e.getMessage(), e);
            }

        } catch (PKIException e) {
            logger.error("UserServletBase: Unable to import user certificate: " + e.getMessage(), e);
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            logger.error("UserServletBase: " + e.getMessage(), e);
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException("Unable to import user certificate: " + e.getMessage(), e);
        }
    }

    private void removeUserCert(String userID, String certID, Locale loc) {

        if (userID == null || userID.isBlank()) throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
        if (certID == null || certID.isBlank()) throw new BadRequestException("Certificate ID is null.");

        try {
            certID = URLDecoder.decode(certID, "UTF-8");
        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }

        UserCertData userCertData = new UserCertData();
        userCertData.setID(certID);
        try {
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            String userCertID = userCertData.getID();

            // no certDN is a success
            if (userCertID == null) {
                auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);
                return;
            }

            userGroupManager.removeUserCert(userID, certID);

            auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);

        } catch (PKIException e) {
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            logger.error("Error: " + e.getMessage(), e);
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException(CMS.getUserMessage(loc, "CMS_USRGRP_USER_MOD_FAILED"));
        }
    }

    private UserMembershipData addUserMembership(String userID, String groupID, Locale loc) {

        if (userID == null || userID.isBlank()) throw new BadRequestException("User ID is null.");
        if (groupID == null || groupID.isBlank()) throw new BadRequestException("Group ID is null.");

        User user = null;

        try {
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            user = userGroupManager.getUser(userID);
        } catch (Exception e) {
            throw new PKIException(CMS.getUserMessage(loc, "CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
        }

        if (user == null) {
            logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
            throw new UserNotFoundException(userID);
        }

        try {
            GroupMemberData groupMemberData = new GroupMemberData();
            groupMemberData.setID(userID);
            groupMemberData.setGroupID(groupID);

            GroupMemberProcessor processor = new GroupMemberProcessor(loc);
            processor.setCMSEngine(engine);
            processor.init();

            processor.addGroupMember(groupMemberData);

            return createUserMembershipData(userID, groupID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    private void removeUserMembership(String userID, String groupID, Locale loc) {

        if (userID == null || userID.isBlank()) throw new BadRequestException("User ID is null.");
        if (groupID == null || groupID.isBlank()) throw new BadRequestException("Group ID is null.");

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(loc);
            processor.setCMSEngine(engine);
            processor.init();

            processor.removeGroupMember(groupID, userID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    private void auditAddUser(String id, UserData userData, String status) {
        auditUser(OpDef.OP_ADD, id, getUserData(userData), status);
    }

    private void auditAddUserCert(String id, UserCertData userCertData, String status) {
        auditUserCert(OpDef.OP_ADD, id, getUserCertData(userCertData), status);
    }

    private void auditModifyUser(String id, UserData userData, String status) {
        auditUser(OpDef.OP_MODIFY, id, getUserData(userData), status);
    }

    private void auditDeleteUser(String id, String status) {
        auditUser(OpDef.OP_DELETE, id, null, status);
    }

    private void auditDeleteUserCert(String id, UserCertData userCertData, String status) {
        auditUserCert(OpDef.OP_DELETE, id, getUserCertData(userCertData), status);
    }

    private void auditUser(String type, String id, Map<String, String> params, String status) {

        Auditor auditor = engine.getAuditor();

        auditor.log(new ConfigRoleEvent(
                auditor.getSubjectID(),
                status,
                auditor.getParamString(ScopeDef.SC_USERS, type, id, params)));
    }

    private void auditUserCert(String type, String id, Map<String, String> params, String status) {

        Auditor auditor = engine.getAuditor();

        auditor.log(new ConfigRoleEvent(
                auditor.getSubjectID(),
                status,
                auditor.getParamString(ScopeDef.SC_USER_CERTS, type, id, params)));
    }

    private Map<String, String> getUserData(UserData userData) {
        Map<String, String> map = new HashMap<>();
        map.put(Constants.PR_USER_FULLNAME, userData.getFullName());
        map.put(Constants.PR_USER_EMAIL, userData.getEmail());
        map.put(Constants.PR_USER_PASSWORD, userData.getPassword());
        map.put(Constants.PR_USER_PHONE, userData.getPhone());
        map.put(Constants.PR_USER_TYPE, userData.getType());
        map.put(Constants.PR_USER_STATE, userData.getState());
        return map;
    }

    private Map<String, String> getUserCertData(UserCertData userData) {
        Map<String, String> map = new HashMap<>();
        map.put(Constants.PR_USER_CERT, userData.getEncoded());
        return map;
    }
}
