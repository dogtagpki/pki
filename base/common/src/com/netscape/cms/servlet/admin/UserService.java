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

import java.net.URI;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import netscape.ldap.LDAPException;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestDataException;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UserNotFoundException;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.ldap.LDAPExceptionConverter;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author Endi S. Dewata
 */
public class UserService extends PKIService implements UserResource {

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
                response.addUser(createUserData(user));
            }

            // count the total entries
            for ( ; users.hasMoreElements(); i++) users.nextElement();

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
            throw new PKIException(getUserMessage("CMS_INTERNAL_ERROR"));
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

                throw new BadRequestDataException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IUser user;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_INTERNAL_ERROR"));
            }

            if (user == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));

                throw new UserNotFoundException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST"));
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

        String userID = userData.getID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestDataException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            if (userID.indexOf(BACK_SLASH) != -1) {
                // backslashes (BS) are not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_RS_ID_BS"));
                throw new BadRequestDataException(getUserMessage("CMS_ADMIN_SRVLT_RS_ID_BS"));
            }

            if (userID.equals(SYSTEM_USER)) {
                // backslashes (BS) are not allowed
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_SPECIAL_ID", userID));
                throw new ForbiddenException(getUserMessage("CMS_ADMIN_SRVLT_SPECIAL_ID", userID));
            }

            IUser user = userGroupManager.createUser(userID);

            String fname = userData.getFullName();
            if (fname == null || fname.length() == 0) {
                String msg = getUserMessage("CMS_USRGRP_USER_ADD_FAILED_1", "full name");

                log(ILogger.LL_FAILURE, msg);
                throw new BadRequestDataException(msg);

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

            try {
                userGroupManager.addUser(user);

                auditAddUser(userID, userData, ILogger.SUCCESS);

                // read the data back
                userData = getUser(userID);

                return Response
                        .created(userData.getLink().getHref())
                        .entity(userData)
                        .type(MediaType.APPLICATION_XML)
                        .build();

            } catch (EUsrGrpException e) {
                log(ILogger.LL_FAILURE, e.toString());

                if (user.getUserID() == null) {
                    throw new BadRequestDataException(getUserMessage("CMS_USRGRP_USER_ADD_FAILED_1", "uid"));
                } else {
                    throw new PKIException(e.getMessage(), e);
                }

            } catch (LDAPException e) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_ADD_USER_FAIL", e.toString()));
                throw LDAPExceptionConverter.toPKIException(e);

            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());
                throw new PKIException(e.getMessage(), e);
            }

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

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestDataException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
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

            try {
                userGroupManager.modifyUser(user);

                auditModifyUser(userID, userData, ILogger.SUCCESS);

                // read the data back
                userData = getUser(userID);

                return Response
                        .ok(userData)
                        .type(MediaType.APPLICATION_XML)
                        .build();

            } catch (Exception e) {
                log(ILogger.LL_FAILURE, e.toString());
                throw new PKIException(getUserMessage("CMS_USRGRP_USER_MOD_FAILED"));
            }

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
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            // get list of groups, and see if uid belongs to any
            Enumeration<IGroup> groups;

            try {
                groups = userGroupManager.findGroups("*");

            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_INTERNAL_ERROR"));
            }

            try {
                while (groups.hasMoreElements()) {
                    IGroup group = groups.nextElement();
                    if (!group.isMember(userID)) continue;

                    userGroupManager.removeUserFromGroup(group, userID);
                }

                // comes out clean of group membership...now remove user
                userGroupManager.removeUser(userID);

                auditDeleteUser(userID, ILogger.SUCCESS);

            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_FAIL_USER_RMV"));
            }

        } catch (PKIException e) {
            auditDeleteUser(userID, ILogger.FAILURE);
            throw e;
        }
    }

    public void log(int level, String message) {
        log(ILogger.S_USRGRP, level, message);
    }

    public void auditAddUser(String id, UserData userData, String status) {
        audit(OpDef.OP_ADD, id, getParams(userData), status);
    }

    public void auditModifyUser(String id, UserData userData, String status) {
        audit(OpDef.OP_MODIFY, id, getParams(userData), status);
    }

    public void auditDeleteUser(String id, String status) {
        audit(OpDef.OP_DELETE, id, null, status);
    }

    public void audit(String type, String id, Map<String, String> params, String status) {
        audit(IAuditor.LOGGING_SIGNED_AUDIT_CONFIG_ROLE, ScopeDef.SC_USERS, type, id, params, status);
    }
}
