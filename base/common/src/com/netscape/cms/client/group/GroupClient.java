//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.cms.client.group;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;

import com.netscape.certsrv.group.GroupCollection;
import com.netscape.certsrv.group.GroupData;
import com.netscape.certsrv.group.GroupMemberCollection;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.group.GroupMemberResource;
import com.netscape.certsrv.group.GroupResource;
import com.netscape.cms.client.ClientConfig;
import com.netscape.cms.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class GroupClient extends PKIClient {

    public GroupResource groupClient;
    public GroupMemberResource groupMemberClient;

    public GroupClient(ClientConfig config) throws URISyntaxException {
        super(config);

        groupClient = createProxy(GroupResource.class);
        groupMemberClient = createProxy(GroupMemberResource.class);
    }

    public GroupCollection findGroups(String groupIDFilter, Integer start, Integer size) {
        return groupClient.findGroups(groupIDFilter, start, size);
    }

    public GroupData getGroup(String groupID) {
        return groupClient.getGroup(groupID);
    }

    public GroupData addGroup(GroupData groupData) {
        @SuppressWarnings("unchecked")
        ClientResponse<GroupData> response = (ClientResponse<GroupData>)groupClient.addGroup(groupData);
        return getEntity(response);
    }

    public GroupData modifyGroup(String groupID, GroupData groupData) {
        @SuppressWarnings("unchecked")
        ClientResponse<GroupData> response = (ClientResponse<GroupData>)groupClient.modifyGroup(groupID, groupData);
        return getEntity(response);
    }

    public void removeGroup(String groupID) {
        groupClient.removeGroup(groupID);
    }

    public GroupMemberCollection findGroupMembers(String groupID, Integer start, Integer size) {
        return groupMemberClient.findGroupMembers(groupID, start, size);
    }

    public GroupMemberData getGroupMember(String groupID, String memberID) {
        return groupMemberClient.getGroupMember(groupID, memberID);
    }

    public GroupMemberData addGroupMember(String groupID, String memberID) {
        @SuppressWarnings("unchecked")
        ClientResponse<GroupMemberData> response = (ClientResponse<GroupMemberData>)groupMemberClient.addGroupMember(groupID, memberID);
        return getEntity(response);
    }

    public void removeGroupMember(String groupID, String memberID) {
        groupMemberClient.removeGroupMember(groupID, memberID);
    }
}
