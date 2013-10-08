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
package com.netscape.certsrv.group;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class GroupClient extends Client {

    public GroupResource groupClient;

    public GroupClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "group");
        init();
    }

    public void init() throws URISyntaxException {
        groupClient = createProxy(GroupResource.class);
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
        return client.getEntity(response);
    }

    public GroupData modifyGroup(String groupID, GroupData groupData) {
        @SuppressWarnings("unchecked")
        ClientResponse<GroupData> response = (ClientResponse<GroupData>)groupClient.modifyGroup(groupID, groupData);
        return client.getEntity(response);
    }

    public void removeGroup(String groupID) {
        groupClient.removeGroup(groupID);
    }

    public GroupMemberCollection findGroupMembers(String groupID, Integer start, Integer size) {
        return groupClient.findGroupMembers(groupID, start, size);
    }

    public GroupMemberData getGroupMember(String groupID, String memberID) {
        return groupClient.getGroupMember(groupID, memberID);
    }

    public GroupMemberData addGroupMember(String groupID, String memberID) {
        @SuppressWarnings("unchecked")
        ClientResponse<GroupMemberData> response = (ClientResponse<GroupMemberData>)groupClient.addGroupMember(groupID, memberID);
        return client.getEntity(response);
    }

    public void removeGroupMember(String groupID, String memberID) {
        groupClient.removeGroupMember(groupID, memberID);
    }
}
