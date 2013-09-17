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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.admin;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.UserNotFoundException;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.user.UserMembershipData;
import com.netscape.certsrv.user.UserMembershipResource;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class UserMembershipService extends PKIService implements UserMembershipResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public IUGSubsystem userGroupManager = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    public UserMembershipData createUserMembershipData(String userID, String groupID) throws UnsupportedEncodingException {

        UserMembershipData userMembershipData = new UserMembershipData();
        userMembershipData.setID(groupID);
        userMembershipData.setUserID(userID);

        URI uri = uriInfo.getBaseUriBuilder().path(UserMembershipResource.class)
                .path("{groupID}")
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

            UserMembershipCollection response = new UserMembershipCollection();

            Enumeration<IGroup> groups = userGroupManager.findGroupsByUser(user.getUserDN());

            int i = 0;

            // skip to the start of the page
            for ( ; i<start && groups.hasMoreElements(); i++) groups.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && groups.hasMoreElements(); i++) {
                IGroup group = groups.nextElement();
                response.addMembership(createUserMembershipData(userID, group.getName()));
            }

            // count the total entries
            for ( ; groups.hasMoreElements(); i++) groups.nextElement();

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
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response addUserMembership(String userID, String groupID) {
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
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public void removeUserMembership(String userID, String groupID) {
        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setUriInfo(uriInfo);
            processor.removeGroupMember(groupID, userID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    public void log(int level, String message) {
        log(ILogger.S_USRGRP, level, message);
    }
}
