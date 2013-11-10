// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.admin;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import netscape.security.pkcs.PKCS7;
import netscape.security.x509.X509CertImpl;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.InternalCertificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.ICertPrettyPrint;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UserNotFoundException;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.user.UserMembershipData;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;

/**
 * @author Endi S. Dewata
 */
public class UserService extends PKIService implements UserResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public final static String BACK_SLASH = "\\";
    public final static String SYSTEM_USER = "$System$";

    public IUGSubsystem userGroupManager = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    public UserData createUserData(IUser user) throws Exception {

        UserData userData = new UserData();

        String id = user.getUserID();
        if (!StringUtils.isEmpty(id)) userData.setID(id);

        String fullName = user.getFullName();
        if (!StringUtils.isEmpty(fullName)) userData.setFullName(fullName);

        String userID = URLEncoder.encode(id, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(UserResource.class).path("{userID}").build(userID);
        userData.setLink(new Link("self", uri));

        return userData;
    }

    /**
     * Searches for users in LDAP directory.
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public UserCollection findUsers(String filter, Integer start, Integer size) {
        try {
            filter = StringUtils.isEmpty(filter) ? "*" : "*"+LDAPUtil.escapeFilter(filter)+"*";
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            Enumeration<IUser> users = userGroupManager.findUsers(filter);

            UserCollection response = new UserCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && users.hasMoreElements(); i++) users.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && users.hasMoreElements(); i++) {
                IUser user = users.nextElement();
                response.addEntry(createUserData(user));
            }

            // count the total entries
            for ( ; users.hasMoreElements(); i++) users.nextElement();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (Exception e) {
            throw new PKIException(getUserMessage("CMS_INTERNAL_ERROR", headers));
        }
    }

    /**
     * List user information. Certificates covered in a separate
     * protocol for findUserCerts(). List of group memberships are
     * also provided.
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public UserData getUser(String userID) {
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IUser user;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_INTERNAL_ERROR", headers));
            }

            if (user == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));

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

            return userData;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * Adds a new user to LDAP server
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */

    @Override
    public Response addUser(UserData userData) {

        if (userData == null) throw new BadRequestException("User data is null.");

        IConfigStore cs = CMS.getConfigStore();
        String userID = userData.getID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            if (userID.indexOf(BACK_SLASH) != -1) {
                // backslashes (BS) are not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_RS_ID_BS"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_RS_ID_BS", headers));
            }

            if (userID.equals(SYSTEM_USER)) {
                // backslashes (BS) are not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_SPECIAL_ID", userID));
                throw new ForbiddenException(getUserMessage("CMS_ADMIN_SRVLT_SPECIAL_ID", headers, userID));
            }

            IUser user = userGroupManager.createUser(userID);

            String fname = userData.getFullName();
            if (fname == null || fname.length() == 0) {
                String msg = getUserMessage("CMS_USRGRP_USER_ADD_FAILED_1", headers, "full name");

                log(ILogger.LL_FAILURE, msg);
                throw new BadRequestException(msg);

            } else {
                user.setFullName(fname);
            }

            String email = userData.getEmail();
            if (email != null) {
                user.setEmail(email);
            } else {
                user.setEmail("");
            }

            String pword = userData.getPassword();
            if (pword != null && !pword.equals("")) {
                IPasswordCheck passwdCheck = CMS.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    throw new EUsrGrpException(passwdCheck.getReason(pword));
                }

                user.setPassword(pword);
            } else {
                user.setPassword("");
            }

            String phone = userData.getPhone();
            if (phone != null) {
                user.setPhone(phone);
            } else {
                user.setPhone("");
            }

            String type = userData.getType();
            if (type != null) {
                user.setUserType(type);
            } else {
                user.setUserType("");
            }

            String state = userData.getState();
            if (state != null) {
                user.setState(state);
            }

            String tpsProfiles = userData.getAttribute(ATTR_TPS_PROFILES);
            String csType = cs.getString("cs.type");
            if (tpsProfiles != null) {
                if (!csType.equals("TPS")) {
                    throw new BadRequestException("Cannot set tpsProfiles on a non-TPS subsystem");
                }
                String[] profiles = tpsProfiles.split(",");
                user.setTpsProfiles(Arrays.asList(profiles));
            }

            userGroupManager.addUser(user);

            auditAddUser(userID, userData, ILogger.SUCCESS);

            // read the data back
            userData = getUser(userID);

            return Response
                    .created(userData.getLink().getHref())
                    .entity(userData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            auditAddUser(userID, userData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditAddUser(userID, userData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * Modifies an existing user in local scope.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response modifyUser(String userID, UserData userData) {

        if (userData == null) throw new BadRequestException("User data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        IConfigStore cs = CMS.getConfigStore();
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IUser user = userGroupManager.createUser(userID);

            String fullName = userData.getFullName();
            if (fullName != null) {
                user.setFullName(fullName);
            }

            String email = userData.getEmail();
            if (email != null) {
                user.setEmail(email);
            }

            String pword = userData.getPassword();
            if (pword != null && !pword.equals("")) {
                IPasswordCheck passwdCheck = CMS.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    throw new EUsrGrpException(passwdCheck.getReason(pword));
                }

                user.setPassword(pword);
            }

            String phone = userData.getPhone();
            if (phone != null) {
                user.setPhone(phone);
            }

            String state = userData.getState();
            if (state != null) {
                user.setState(state);
            }

            String tpsProfiles = userData.getAttribute(ATTR_TPS_PROFILES);
            String csType = cs.getString("cs.type");
            if (tpsProfiles != null) {
                if (!csType.equals("TPS")) {
                    throw new BadRequestException("Cannot set tpsProfiles on a non-TPS subsystem");
                }
                String[] profiles = tpsProfiles.split(",");
                user.setTpsProfiles(Arrays.asList(profiles));
            }

            userGroupManager.modifyUser(user);

            auditModifyUser(userID, userData, ILogger.SUCCESS);

            // read the data back
            userData = getUser(userID);

            return Response
                    .ok(userData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            auditModifyUser(userID, userData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditModifyUser(userID, userData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * removes a user. user not removed if belongs to any group
     * (Administrators should remove the user from "uniquemember" of
     * any group he/she belongs to before trying to remove the user
     * itself.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public void removeUser(String userID) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            // get list of groups, and see if uid belongs to any
            Enumeration<IGroup> groups = userGroupManager.findGroups("*");

            while (groups.hasMoreElements()) {
                IGroup group = groups.nextElement();
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

    public UserCertData createUserCertData(String userID, X509Certificate cert) throws Exception {

        UserCertData userCertData = new UserCertData();

        userCertData.setVersion(cert.getVersion());
        userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
        userCertData.setIssuerDN(cert.getIssuerDN().toString());
        userCertData.setSubjectDN(cert.getSubjectDN().toString());

        userID = URLEncoder.encode(userID, "UTF-8");
        String certID = URLEncoder.encode(userCertData.getID(), "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder()
                .path(UserResource.class)
                .path("{userID}/certs/{certID}")
                .build(userID, certID);
        userCertData.setLink(new Link("self", uri));

        return userCertData;
    }

    /**
     * List user certificate(s)
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public UserCertCollection findUserCerts(String userID, Integer start, Integer size) {
        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IUser user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST", headers));
            }

            if (user == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            X509Certificate[] certs = user.getX509Certificates();
            if (certs == null) certs = new X509Certificate[0];
            Iterator<X509Certificate> entries = Arrays.asList(certs).iterator();

            UserCertCollection response = new UserCertCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && entries.hasNext(); i++) entries.next();

            // return entries up to the page size
            for ( ; i<start+size && entries.hasNext(); i++) {
                response.addEntry(createUserCertData(userID, entries.next()));
            }

            // count the total entries
            for ( ; entries.hasNext(); i++) entries.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public UserCertData getUserCert(String userID, String certID) {

        if (certID == null) throw new BadRequestException("Certificate ID is null.");

        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));

                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IUser user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST", headers));
            }

            if (user == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
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

                ICertPrettyPrint print = CMS.getCertPrettyPrint(cert);
                userCertData.setPrettyPrint(print.toString(getLocale(headers)));

                // add base64 encoding
                String base64 = CMS.getEncodedCert(cert);
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

    /**
     * Adds a certificate to a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response addUserCert(String userID, UserCertData userCertData) {

        if (userCertData == null) throw new BadRequestException("Certificate data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IUser user = userGroupManager.createUser(userID);

            String encoded = userCertData.getEncoded();
            encoded = Cert.normalizeCertStrAndReq(encoded);
            encoded = Cert.stripBrackets(encoded);

            // no cert is a success
            if (encoded == null) {
                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);
                return Response.ok().build();
            }

            // only one cert added per operation
            X509Certificate cert = null;

            // Base64 decode cert
            byte binaryCert[] = Utils.base64decode(encoded);

            try {
                cert = new X509CertImpl(binaryCert);

            } catch (CertificateException e) {
                // ignore
            }

            if (cert == null) {
                // cert chain direction
                boolean assending = true;

                // could it be a pkcs7 blob?
                CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_IS_PK_BLOB"));

                try {
                    CryptoManager manager = CryptoManager.getInstance();

                    PKCS7 pkcs7 = new PKCS7(binaryCert);

                    X509Certificate p7certs[] = pkcs7.getCertificates();

                    if (p7certs.length == 0) {
                        throw new BadRequestException(getUserMessage("CMS_USRGRP_SRVLT_CERT_ERROR", headers));
                    }

                    // fix for 370099 - cert ordering can not be assumed
                    // find out the ordering ...

                    // self-signed and alone? take it. otherwise test
                    // the ordering
                    if (p7certs[0].getSubjectDN().toString().equals(
                            p7certs[0].getIssuerDN().toString()) &&
                            (p7certs.length == 1)) {
                        cert = p7certs[0];
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_SINGLE_CERT_IMPORT"));

                    } else if (p7certs[0].getIssuerDN().toString().equals(p7certs[1].getSubjectDN().toString())) {
                        cert = p7certs[0];
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_ACEND_ORD"));

                    } else if (p7certs[1].getIssuerDN().toString().equals(p7certs[0].getSubjectDN().toString())) {
                        assending = false;
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_DESC_ORD"));
                        cert = p7certs[p7certs.length - 1];

                    } else {
                        // not a chain, or in random order
                        CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_BAD_CHAIN"));
                        throw new BadRequestException(getUserMessage("CMS_USRGRP_SRVLT_CERT_ERROR", headers));
                    }

                    CMS.debug("UserCertResourceService: "
                            + CMS.getLogMessage("ADMIN_SRVLT_CHAIN_STORED_DB", String.valueOf(p7certs.length)));

                    int j = 0;
                    int jBegin = 0;
                    int jEnd = 0;

                    if (assending == true) {
                        jBegin = 1;
                        jEnd = p7certs.length;
                    } else {
                        jBegin = 0;
                        jEnd = p7certs.length - 1;
                    }

                    // store the chain into cert db, except for the user cert
                    for (j = jBegin; j < jEnd; j++) {
                        CMS.debug("UserCertResourceService: "
                                + CMS.getLogMessage("ADMIN_SRVLT_CERT_IN_CHAIN", String.valueOf(j),
                                        String.valueOf(p7certs[j].getSubjectDN())));
                        org.mozilla.jss.crypto.X509Certificate leafCert =
                                manager.importCACertPackage(p7certs[j].getEncoded());

                        if (leafCert == null) {
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NULL"));
                        } else {
                            CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NON_NULL"));
                        }

                        if (leafCert instanceof InternalCertificate) {
                            ((InternalCertificate) leafCert).setSSLTrust(
                                    InternalCertificate.VALID_CA |
                                            InternalCertificate.TRUSTED_CA |
                                            InternalCertificate.TRUSTED_CLIENT_CA);
                        } else {
                            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NOT_INTERNAL_CERT",
                                    String.valueOf(p7certs[j].getSubjectDN())));
                        }
                    }

                    /*
                    } catch (CryptoManager.UserCertConflictException e) {
                        // got a "user cert" in the chain, most likely the CA
                        // cert of this instance, which has a private key.  Ignore
                        log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_PKS7_IGNORED", e.toString()));
                    */
                } catch (PKIException e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", e.toString()));
                    throw e;
                } catch (Exception e) {
                    log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", e.toString()));
                    throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_CERT_ERROR", headers));
                }
            }

            try {
                CMS.debug("UserCertResourceService: " + CMS.getLogMessage("ADMIN_SRVLT_BEFORE_VALIDITY"));
                cert.checkValidity(); // throw exception if fails

                user.setX509Certificates(new X509Certificate[] { cert });
                userGroupManager.addUserCert(user);

                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);

                // read the data back

                userCertData.setVersion(cert.getVersion());
                userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
                userCertData.setIssuerDN(cert.getIssuerDN().toString());
                userCertData.setSubjectDN(cert.getSubjectDN().toString());
                String certID = userCertData.getID();

                userCertData = getUserCert(userID, URLEncoder.encode(certID, "UTF-8"));

                return Response
                        .created(userCertData.getLink().getHref())
                        .entity(userCertData)
                        .type(MediaType.APPLICATION_XML)
                        .build();

            } catch (CertificateExpiredException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_ADD_CERT_EXPIRED",
                        String.valueOf(cert.getSubjectDN())));
                throw new BadRequestException(getUserMessage("CMS_USRGRP_SRVLT_CERT_EXPIRED", headers));

            } catch (CertificateNotYetValidException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_CERT_NOT_YET_VALID",
                        String.valueOf(cert.getSubjectDN())));
                throw new BadRequestException(getUserMessage("CMS_USRGRP_SRVLT_CERT_NOT_YET_VALID", headers));
            }

        } catch (PKIException e) {
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException(getUserMessage("CMS_USRGRP_USER_MOD_FAILED", headers));
        }
    }

    /**
     * Removes a certificate for a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * In this method, "certDN" is actually a combination of version, serialNumber, issuerDN, and SubjectDN.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public void removeUserCert(String userID, String certID) {

        if (userID == null) throw new BadRequestException("User ID is null.");
        if (certID == null) throw new BadRequestException("Certificate ID is null.");

        try {
            certID = URLDecoder.decode(certID, "UTF-8");
        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }

        UserCertData userCertData = new UserCertData();
        userCertData.setID(certID);
        removeUserCert(userID, userCertData);
    }

    public void removeUserCert(String userID, UserCertData userCertData) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IUser user = userGroupManager.createUser(userID);
            String certID = userCertData.getID();

            // no certDN is a success
            if (certID == null) {
                auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);
                return;
            }

            user.setCertDN(certID);

            userGroupManager.removeUserCert(user);

            auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);

        } catch (PKIException e) {
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException(getUserMessage("CMS_USRGRP_USER_MOD_FAILED", headers));
        }
    }


    public UserMembershipData createUserMembershipData(String userID, String groupID) throws UnsupportedEncodingException {

        UserMembershipData userMembershipData = new UserMembershipData();
        userMembershipData.setID(groupID);
        userMembershipData.setUserID(userID);

        URI uri = uriInfo.getBaseUriBuilder()
                .path(UserResource.class)
                .path("{userID}/memberships/{groupID}")
                .build(
                        URLEncoder.encode(userID, "UTF-8"),
                        URLEncoder.encode(groupID, "UTF-8"));

        userMembershipData.setLink(new Link("self", uri));

        return userMembershipData;
    }

    @Override
    public UserMembershipCollection findUserMemberships(String userID, Integer start, Integer size) {
        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IUser user = userGroupManager.getUser(userID);

            if (user == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            Enumeration<IGroup> groups = userGroupManager.findGroupsByUser(user.getUserDN());

            UserMembershipCollection response = new UserMembershipCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && groups.hasMoreElements(); i++) groups.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && groups.hasMoreElements(); i++) {
                IGroup group = groups.nextElement();
                response.addEntry(createUserMembershipData(userID, group.getName()));
            }

            // count the total entries
            for ( ; groups.hasMoreElements(); i++) groups.nextElement();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response addUserMembership(String userID, String groupID) {

        if (userID == null) throw new BadRequestException("User ID is null.");
        if (groupID == null) throw new BadRequestException("Group ID is null.");

        try {
            GroupMemberData groupMemberData = new GroupMemberData();
            groupMemberData.setID(userID);
            groupMemberData.setGroupID(groupID);

            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setUriInfo(uriInfo);
            processor.addGroupMember(groupMemberData);

            UserMembershipData userMembershipData = createUserMembershipData(userID, groupID);

            return Response
                    .created(userMembershipData.getLink().getHref())
                    .entity(userMembershipData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public void removeUserMembership(String userID, String groupID) {

        if (userID == null) throw new BadRequestException("User ID is null.");
        if (groupID == null) throw new BadRequestException("Group ID is null.");

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setUriInfo(uriInfo);
            processor.removeGroupMember(groupID, userID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    public void log(int level, String message) {
        log(ILogger.S_USRGRP, level, message);
    }

    public void auditAddUser(String id, UserData userData, String status) {
        auditUser(OpDef.OP_ADD, id, getParams(userData), status);
    }

    public void auditModifyUser(String id, UserData userData, String status) {
        auditUser(OpDef.OP_MODIFY, id, getParams(userData), status);
    }

    public void auditDeleteUser(String id, String status) {
        auditUser(OpDef.OP_DELETE, id, null, status);
    }

    public void auditAddUserCert(String id, UserCertData userCertData, String status) {
        auditUserCert(OpDef.OP_ADD, id, getParams(userCertData), status);
    }

    public void auditDeleteUserCert(String id, UserCertData userCertData, String status) {
        auditUserCert(OpDef.OP_DELETE, id, getParams(userCertData), status);
    }

    public void auditUser(String type, String id, Map<String, String> params, String status) {
        audit(IAuditor.LOGGING_SIGNED_AUDIT_CONFIG_ROLE, ScopeDef.SC_USERS, type, id, params, status);
    }

    public void auditUserCert(String type, String id, Map<String, String> params, String status) {
        audit(IAuditor.LOGGING_SIGNED_AUDIT_CONFIG_ROLE, ScopeDef.SC_USER_CERTS, type, id, params, status);
    }
}
