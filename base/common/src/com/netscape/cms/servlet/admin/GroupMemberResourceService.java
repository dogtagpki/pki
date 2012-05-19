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

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.group.GroupMemberResource;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.CMSResourceService;

/**
 * @author Endi S. Dewata
 */
public class GroupMemberResourceService extends CMSResourceService implements GroupMemberResource {

    public final static int DEFAULT_SIZE = 20;

    public final static String MULTI_ROLE_ENABLE = "multiroles.enable";
    public final static String MULTI_ROLE_ENFORCE_GROUP_LIST = "multiroles.false.groupEnforceList";

    public static String[] multiRoleGroupEnforceList;

    public IUGSubsystem userGroupManager = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    public GroupMemberData createGroupMemberData(String memberID) throws Exception {

        GroupMemberData groupMemberData = new GroupMemberData();

        groupMemberData.setID(memberID);

        String userID = URLEncoder.encode(memberID, "UTF-8");
        URI uri = uriInfo.getBaseUriBuilder().path(UserResource.class).path("{userID}").build(userID);
        groupMemberData.setLink(new Link("self", uri));

        return groupMemberData;
    }

    @Override
    public GroupMemberCollection findGroupMembers(String groupID, Integer start, Integer size) {
        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new CMSException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IGroup group = userGroupManager.getGroupFromName(groupID);
            if (group == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));
                throw new CMSException(getUserMessage("CMS_USRGRP_SRVLT_GROUP_NOT_EXIST"));
            }

            GroupMemberCollection response = new GroupMemberCollection();

            Enumeration<String> members = group.getMemberNames();

            int i = 0;

            // skip to the start of the page
            for ( ; i<start && members.hasMoreElements(); i++) members.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && members.hasMoreElements(); i++) {
                String memberID = members.nextElement();
                response.addMember(createGroupMemberData(memberID));
            }

            // count the total entries
            for ( ; members.hasMoreElements(); i++) members.nextElement();

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (CMSException e) {
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new CMSException(getUserMessage("CMS_INTERNAL_ERROR"));
        }
    }

    @Override
    public Response addGroupMember(String groupID, String memberID) {
        GroupMemberData groupMemberData = new GroupMemberData();
        groupMemberData.setID(memberID);
        return addGroupMember(groupID, groupMemberData);
    }

    public Response addGroupMember(String groupID, GroupMemberData groupMemberData) {

        try {
            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new CMSException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IGroup group = userGroupManager.getGroupFromName(groupID);
            if (group == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));
                throw new CMSException(getUserMessage("CMS_USRGRP_SRVLT_GROUP_NOT_EXIST"));
            }

            String memberID = groupMemberData.getID();
            boolean multiRole = true;

            try {
                IConfigStore config = CMS.getConfigStore();
                multiRole = config.getBoolean(MULTI_ROLE_ENABLE);
            } catch (Exception e) {
                // ignore
            }

            if (multiRole) {
                // a user can be a member of multiple groups
                userGroupManager.addUserToGroup(group, memberID);

            } else {
                // a user can be a member of at most one group in the enforce list
                if (isGroupInMultiRoleEnforceList(groupID)) {
                    // make sure the user is not already a member in another group in the list
                    if (!isDuplicate(groupID, memberID)) {
                        userGroupManager.addUserToGroup(group, memberID);
                    } else {
                        throw new EBaseException(CMS.getUserMessage("CMS_BASE_DUPLICATE_ROLES", memberID));
                    }

                } else {
                    // the user can be a member of multiple groups outside the list
                    userGroupManager.addUserToGroup(group, memberID);
                }
            }

            // for audit log
            SessionContext sContext = SessionContext.getContext();
            String adminId = (String) sContext.get(SessionContext.USER_ID);

            logger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                    AuditFormat.LEVEL, AuditFormat.ADDUSERGROUPFORMAT,
                    new Object[] { adminId, memberID, groupID });

            auditAddGroupMember(groupID, groupMemberData, ILogger.SUCCESS);

            // read the data back
            groupMemberData = getGroupMember(groupID, memberID);

            return Response
                    .created(groupMemberData.getLink().getHref())
                    .entity(groupMemberData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (CMSException e) {
            auditAddGroupMember(groupID, groupMemberData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            auditAddGroupMember(groupID, groupMemberData, ILogger.FAILURE);
            throw new CMSException(getUserMessage("CMS_USRGRP_USER_ADD_FAILED"));
        }
    }

    public boolean isGroupInMultiRoleEnforceList(String groupID) {

        if (groupID == null || groupID.equals("")) {
            return true;
        }

        String groupList = null;
        if (multiRoleGroupEnforceList == null) {
            try {
                IConfigStore config = CMS.getConfigStore();
                groupList = config.getString(MULTI_ROLE_ENFORCE_GROUP_LIST);
            } catch (Exception e) {
                // ignore
            }

            if (groupList != null && !groupList.equals("")) {
                multiRoleGroupEnforceList = groupList.split(",");
                for (int j = 0; j < multiRoleGroupEnforceList.length; j++) {
                    multiRoleGroupEnforceList[j] = multiRoleGroupEnforceList[j].trim();
                }
            }
        }

        if (multiRoleGroupEnforceList == null)
            return true;

        for (int i = 0; i < multiRoleGroupEnforceList.length; i++) {
            if (groupID.equals(multiRoleGroupEnforceList[i])) {
                return true;
            }
        }

        return false;
    }

    public boolean isDuplicate(String groupID, String memberID) {

        // Let's not mess with users that are already a member of this group
        try {
            boolean isMember = userGroupManager.isMemberOf(memberID, groupID);
            if (isMember == true) return false;

        } catch (Exception e) {
            // ignore
        }

        try {
            Enumeration<IGroup> groups = userGroupManager.listGroups("*");
            while (groups.hasMoreElements()) {
                IGroup group = groups.nextElement();
                String name = group.getName();

                Enumeration<IGroup> g = userGroupManager.findGroups(name);
                IGroup g1 = g.nextElement();

                if (!name.equals(groupID)) {
                    if (isGroupInMultiRoleEnforceList(name)) {
                        Enumeration<String> members = g1.getMemberNames();
                        while (members.hasMoreElements()) {
                            String m1 = members.nextElement();
                            if (m1.equals(memberID))
                                return true;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }

        return false;
    }

    @Override
    public GroupMemberData getGroupMember(String groupID, String memberID) {

        try {
            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new CMSException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IGroup group = userGroupManager.getGroupFromName(groupID);
            if (group == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));
                throw new CMSException(getUserMessage("CMS_USRGRP_SRVLT_GROUP_NOT_EXIST"));
            }

            Enumeration<String> e = group.getMemberNames();
            while (e.hasMoreElements()) {
                String memberName = e.nextElement();
                if (!memberName.equals(memberID)) continue;

                GroupMemberData groupMemberData = createGroupMemberData(memberID);
                return groupMemberData;
            }

            throw new CMSException("Group member not found");

        } catch (CMSException e) {
            throw e;

        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            throw new CMSException(e.getMessage());
        }
    }

    @Override
    public void removeGroupMember(String groupID, String memberID) {
        GroupMemberData groupMemberData = new GroupMemberData();
        groupMemberData.setID(memberID);
        removeGroupMember(groupID, groupMemberData);
    }

    public void removeGroupMember(String groupID, GroupMemberData groupMemberData) {
        try {
            if (groupID == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new CMSException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            IGroup group = userGroupManager.getGroupFromName(groupID);
            if (group == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));
                throw new CMSException(getUserMessage("CMS_USRGRP_SRVLT_GROUP_NOT_EXIST"));
            }

            String member = groupMemberData.getID();
            userGroupManager.removeUserFromGroup(group, member);

            // for audit log
            SessionContext sContext = SessionContext.getContext();
            String adminId = (String) sContext.get(SessionContext.USER_ID);

            logger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                    AuditFormat.LEVEL, AuditFormat.REMOVEUSERGROUPFORMAT,
                    new Object[] { adminId, member, groupID });

            auditDeleteGroupMember(groupID, groupMemberData, ILogger.SUCCESS);

        } catch (CMSException e) {
            auditDeleteGroupMember(groupID, groupMemberData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            log(ILogger.LL_FAILURE, e.toString());
            auditDeleteGroupMember(groupID, groupMemberData, ILogger.FAILURE);
            throw new CMSException(getUserMessage("CMS_USRGRP_USER_ADD_FAILED"));
        }
    }

    public void log(int level, String message) {
        log(ILogger.S_USRGRP, level, message);
    }

    public void auditAddGroupMember(String groupID, GroupMemberData groupMemberData, String status) {
        audit(OpDef.OP_ADD, groupID, getParams(groupMemberData), status);
    }

    public void auditDeleteGroupMember(String groupID, GroupMemberData groupMemberData, String status) {
        audit(OpDef.OP_DELETE, groupID, getParams(groupMemberData), status);
    }

    public void audit(String type, String id, Map<String, String> params, String status) {
        audit(IAuditor.LOGGING_SIGNED_AUDIT_CONFIG_ROLE, ScopeDef.SC_GROUP_MEMBERS, type, id, params, status);
    }
}
