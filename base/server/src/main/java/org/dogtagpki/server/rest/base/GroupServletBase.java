//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.base;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.rest.v2.PKIServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.group.GroupCollection;
import com.netscape.certsrv.group.GroupData;
import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.group.GroupNotFoundException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.cms.servlet.admin.GroupMemberProcessor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class GroupServletBase {
    public static final Logger logger = LoggerFactory.getLogger(GroupServletBase.class);

    private CMSEngine engine;
    private UGSubsystem userGroupManager;

    public GroupServletBase(CMSEngine engine) {
        this.engine = engine;
        this.userGroupManager = engine.getUGSubsystem();
    }

    public GroupCollection findGroups(String filter, int start, int size) {
        if (filter != null && filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }
        try {
            Enumeration<Group> groups = userGroupManager.listGroups(filter);

            GroupCollection response = new GroupCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && groups.hasMoreElements(); i++) groups.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && groups.hasMoreElements(); i++) {
                Group group = groups.nextElement();
                response.addEntry(createGroupData(group));
            }

            // count the total entries
            for ( ; groups.hasMoreElements(); i++) groups.nextElement();
            response.setTotal(i);

            return response;

        } catch (Exception e) {
            logger.error("GroupServletBase: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public GroupData addGroup(GroupData groupData, Locale loc) {

        if (groupData == null) throw new BadRequestException("Group data is null.");

        String groupID = groupData.getGroupID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (groupID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            Group group = userGroupManager.createGroup(groupID);

            // add description if specified
            String description = groupData.getDescription();
            if (description != null && !description.equals("")) {
                group.set(Group.ATTR_DESCRIPTION, description);
            }

            // allow adding a group with no members
            userGroupManager.addGroup(group);

            auditAddGroup(groupID, groupData, ILogger.SUCCESS);

            // read the data back
            return getGroup(groupID, loc);

        } catch (PKIException e) {
            auditAddGroup(groupID, groupData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditAddGroup(groupID, groupData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    public GroupData getGroup(String groupId, Locale loc) {

        try {
            if (groupId == null || groupId.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            Group group = userGroupManager.getGroupFromName(groupId);

            if (group == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_GROUP_NOT_EXIST"));
                throw new GroupNotFoundException(groupId);
            }

            return createGroupData(group);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(CMS.getUserMessage(loc, "CMS_INTERNAL_ERROR"));
        }
    }

    public GroupData modifyGroup(String groupId, GroupData groupData, Locale loc) {

        if (groupData == null) throw new BadRequestException("Group data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (groupId == null || groupId.isBlank()) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            Group group = userGroupManager.getGroupFromName(groupId);

            if (group == null) {
                throw new ResourceNotFoundException("Group " + groupId + "  not found.");
            }

            // update description if specified
            String description = groupData.getDescription();
            if (description != null) {
                if (description.equals("")) { // remove value if empty
                    group.delete(Group.ATTR_DESCRIPTION);
                } else { // otherwise replace value
                    group.set(Group.ATTR_DESCRIPTION, description);
                }
            }

            // allow adding a group with no members, except "Certificate
            // Server Administrators"
            userGroupManager.modifyGroup(group);

            auditModifyGroup(groupId, groupData, ILogger.SUCCESS);

            // read the data back
            return getGroup(groupId, loc);

        } catch (PKIException e) {
            auditModifyGroup(groupId, groupData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditModifyGroup(groupId, groupData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
}

    public void removeGroup(String groupId, Locale loc) {
        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (groupId == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(CMS.getUserMessage(loc, "CMS_ADMIN_SRVLT_NULL_RS_ID"));
            }

            // if fails, let the exception fall through
            userGroupManager.removeGroup(groupId);

            auditDeleteGroup(groupId, ILogger.SUCCESS);
        } catch (PKIException e) {
            auditDeleteGroup(groupId, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditDeleteGroup(groupId, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }


    public GroupMemberCollection findGroupMembers(String groupId, String filter, int start, int size, Locale loc) {
        logger.debug("GroupServletBase.findGroupMembers({}, {}", groupId,  filter);

        if (groupId == null || groupId.isBlank()) throw new BadRequestException("Group ID is null.");

        if (filter != null && filter.length() < 3) {
            throw new BadRequestException("Filter is too short.");
        }

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(loc);
            processor.setCMSEngine(engine);
            processor.init();

            return processor.findGroupMembers(groupId, filter, start, size);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    public GroupMemberData addGroupMember(String groupId, GroupMemberData groupMemberData, Locale loc) {
        if (groupId == null || groupId.isBlank()) throw new BadRequestException("Group ID is null.");
        if (groupMemberData == null || groupMemberData.getID() == null) throw new BadRequestException("Member ID is null.");
        groupMemberData.setGroupID(groupId);

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(loc);
            processor.setCMSEngine(engine);
            processor.init();

            return processor.addGroupMember(groupMemberData);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    public GroupMemberData getGroupMember(String groupId, String memberId, Locale loc) {
        if (groupId == null || groupId.isBlank()) throw new BadRequestException("Group ID is null.");
        if (memberId == null || memberId.isBlank()) throw new BadRequestException("Member ID is null.");

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(loc);
            processor.setCMSEngine(engine);
            processor.init();

            return processor.getGroupMember(groupId, memberId);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    public void removeGroupMember(String groupId, String memberId, Locale loc) {
        if (groupId == null || groupId.isBlank()) throw new BadRequestException("Group ID is null.");
        if (memberId == null || memberId.isBlank()) throw new BadRequestException("Member ID is null.");

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(loc);
            processor.setCMSEngine(engine);
            processor.init();

            processor.removeGroupMember(groupId, memberId);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    private GroupData createGroupData(Group group) throws Exception {

        GroupData groupData = new GroupData();

        String groupID = group.getGroupID();
        if (!StringUtils.isEmpty(groupID)) {
            groupData.setID(groupID);
            groupData.setGroupID(groupID);
        }

        String description = group.getDescription();
        if (!StringUtils.isEmpty(description)) groupData.setDescription(description);

        return groupData;
    }

    private void auditAddGroup(String groupID, GroupData groupData, String status) {
        audit(OpDef.OP_ADD, groupID, getGroupData(groupData), status);
    }

    private void auditModifyGroup(String groupID, GroupData groupData, String status) {
        audit(OpDef.OP_MODIFY, groupID, getGroupData(groupData), status);
    }

    private void auditDeleteGroup(String groupID, String status) {
        audit(OpDef.OP_DELETE, groupID, null, status);
    }

    private void audit(String type, String id, Map<String, String> params, String status) {

        Auditor auditor = engine.getAuditor();

        auditor.log(new ConfigRoleEvent(
                auditor.getSubjectID(),
                status,
                auditor.getParamString(ScopeDef.SC_GROUPS, type, id, params)));
    }

    private Map<String, String> getGroupData(GroupData groupData) {
        Map<String, String> map = new HashMap<>();
        map.put(Constants.PR_GROUP_DESC, groupData.getDescription());
        return map;
    }

}
