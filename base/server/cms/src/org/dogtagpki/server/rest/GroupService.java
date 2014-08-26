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

package org.dogtagpki.server.rest;

import java.net.URI;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.group.GroupCollection;
import com.netscape.certsrv.group.GroupData;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.group.GroupNotFoundException;
import com.netscape.certsrv.group.GroupResource;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IGroupConstants;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.cms.servlet.admin.GroupMemberProcessor;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class GroupService extends PKIService implements GroupResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    public IUGSubsystem userGroupManager = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    public GroupData createGroupData(IGroup group) throws Exception {

        GroupData groupData = new GroupData();

        String groupID = group.getGroupID();
        if (!StringUtils.isEmpty(groupID)) {
            groupData.setID(groupID);
            groupData.setGroupID(groupID);
        }

        String description = group.getDescription();
        if (!StringUtils.isEmpty(description)) groupData.setDescription(description);

        String encodedGroupID = URLEncoder.encode(groupData.getID(), "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(GroupResource.class).path("{groupID}").build(encodedGroupID);
        groupData.setLink(new Link("self", uri));

        return groupData;
    }

    /**
     * Searches for users in LDAP directory.
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public Response findGroups(String filter, Integer start, Integer size) {

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        try {
            Enumeration<IGroup> groups = userGroupManager.listGroups(filter);

            GroupCollection response = new GroupCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && groups.hasMoreElements(); i++) groups.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && groups.hasMoreElements(); i++) {
                IGroup group = groups.nextElement();
                response.addEntry(createGroupData(group));
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

            return createOKResponse(response);

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException(e);
        }
    }

    /**
     * finds a group
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public Response getGroup(String groupID) {
        return createOKResponse(getGroupData(groupID));
    }

    public GroupData getGroupData(String groupID) {

        try {
            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IGroup group = userGroupManager.getGroupFromName(groupID);
            if (group == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));
                throw new GroupNotFoundException(groupID);
            }

            return createGroupData(group);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(getUserMessage("CMS_INTERNAL_ERROR", headers));
        }
    }

    /**
     * Adds a new group in local scope.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#group
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response addGroup(GroupData groupData) {

        if (groupData == null) throw new BadRequestException("Group data is null.");

        String groupID = groupData.getGroupID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IGroup group = userGroupManager.createGroup(groupID);

            // add description if specified
            String description = groupData.getDescription();
            if (description != null && !description.equals("")) {
                group.set(IGroupConstants.ATTR_DESCRIPTION, description);
            }

            // allow adding a group with no members
            userGroupManager.addGroup(group);

            auditAddGroup(groupID, groupData, ILogger.SUCCESS);

            // read the data back
            groupData = getGroupData(groupID);

            return createCreatedResponse(groupData, groupData.getLink().getHref());

        } catch (PKIException e) {
            auditAddGroup(groupID, groupData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditAddGroup(groupID, groupData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * modifies a group
     * <P>
     *
     * last person of the super power group "Certificate Server Administrators" can never be removed.
     * <P>
     *
     * http://warp.mcom.com/server/certificate/columbo/design/ ui/admin-protocol-definition.html#group
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response modifyGroup(String groupID, GroupData groupData) {

        if (groupData == null) throw new BadRequestException("Group data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            IGroup group = userGroupManager.getGroupFromName(groupID);

            if (group == null) {
                throw new ResourceNotFoundException("Group " + groupID + "  not found.");
            }

            // update description if specified
            String description = groupData.getDescription();
            if (description != null) {
                if (description.equals("")) { // remove value if empty
                    group.delete(IGroupConstants.ATTR_DESCRIPTION);
                } else { // otherwise replace value
                    group.set(IGroupConstants.ATTR_DESCRIPTION, description);
                }
            }

            // allow adding a group with no members, except "Certificate
            // Server Administrators"
            userGroupManager.modifyGroup(group);

            auditModifyGroup(groupID, groupData, ILogger.SUCCESS);

            // read the data back
            groupData = getGroupData(groupID);

            return createOKResponse(groupData);

        } catch (PKIException e) {
            auditModifyGroup(groupID, groupData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditModifyGroup(groupID, groupData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * removes a group
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#group
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response removeGroup(String groupID) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            // if fails, let the exception fall through
            userGroupManager.removeGroup(groupID);

            auditDeleteGroup(groupID, ILogger.SUCCESS);

            return createNoContentResponse();

        } catch (PKIException e) {
            auditDeleteGroup(groupID, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditDeleteGroup(groupID, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response findGroupMembers(String groupID, String filter, Integer start, Integer size) {

        CMS.debug("GroupService.findGroupMembers(" + groupID + ", " + filter + ")");

        if (groupID == null) throw new BadRequestException("Group ID is null.");

        if (filter != null && filter.length() < 3) {
            throw new BadRequestException("Filter is too short.");
        }

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setUriInfo(uriInfo);
            return createOKResponse(processor.findGroupMembers(groupID, filter, start, size));

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response getGroupMember(String groupID, String memberID) {

        if (groupID == null) throw new BadRequestException("Group ID is null.");
        if (memberID == null) throw new BadRequestException("Member ID is null.");

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setUriInfo(uriInfo);
            return createOKResponse(processor.getGroupMember(groupID, memberID));

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response addGroupMember(String groupID, GroupMemberData groupMemberData) {
        if (groupID == null) throw new BadRequestException("Group ID is null.");
        if (groupMemberData.getID() == null) throw new BadRequestException("Member ID is null.");
        groupMemberData.setGroupID(groupID);

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setUriInfo(uriInfo);
            groupMemberData = processor.addGroupMember(groupMemberData);

            return createCreatedResponse(groupMemberData, groupMemberData.getLink().getHref());

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response removeGroupMember(String groupID, String memberID) {

        if (groupID == null) throw new BadRequestException("Group ID is null.");
        if (memberID == null) throw new BadRequestException("Member ID is null.");

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setUriInfo(uriInfo);
            processor.removeGroupMember(groupID, memberID);

            return createNoContentResponse();

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

    public void auditAddGroup(String groupID, GroupData groupData, String status) {
        audit(OpDef.OP_ADD, groupID, getParams(groupData), status);
    }

    public void auditModifyGroup(String groupID, GroupData groupData, String status) {
        audit(OpDef.OP_MODIFY, groupID, getParams(groupData), status);
    }

    public void auditDeleteGroup(String groupID, String status) {
        audit(OpDef.OP_DELETE, groupID, null, status);
    }

    public void audit(String type, String id, Map<String, String> params, String status) {
        audit(IAuditor.LOGGING_SIGNED_AUDIT_CONFIG_ROLE, ScopeDef.SC_GROUPS, type, id, params, status);
    }
}
