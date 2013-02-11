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

import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.group.GroupMemberResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class GroupMemberService extends PKIService implements GroupMemberResource {

    @Override
    public GroupMemberCollection findGroupMembers(String groupID, Integer start, Integer size) {
        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale());
            processor.setUriInfo(uriInfo);
            return processor.findGroupMembers(groupID, start, size);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public GroupMemberData getGroupMember(String groupID, String memberID) {
        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale());
            processor.setUriInfo(uriInfo);
            return processor.getGroupMember(groupID, memberID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response addGroupMember(String groupID, String memberID) {
        GroupMemberData groupMemberData = new GroupMemberData();
        groupMemberData.setID(memberID);
        groupMemberData.setGroupID(groupID);
        return addGroupMember(groupMemberData);
    }

    public Response addGroupMember(GroupMemberData groupMemberData) {
        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale());
            processor.setUriInfo(uriInfo);
            return processor.addGroupMember(groupMemberData);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public void removeGroupMember(String groupID, String memberID) {
        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale());
            processor.setUriInfo(uriInfo);
            processor.removeGroupMember(groupID, memberID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage(), e);
        }
    }
}
