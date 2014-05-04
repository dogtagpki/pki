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

import javax.ws.rs.core.Response;

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
        Response response = groupClient.findGroups(groupIDFilter, start, size);
        return client.getEntity(response, GroupCollection.class);
    }

    public GroupData getGroup(String groupID) {
        Response response = groupClient.getGroup(groupID);
        return client.getEntity(response, GroupData.class);
    }

    public GroupData addGroup(GroupData groupData) {
        Response response = groupClient.addGroup(groupData);
        return client.getEntity(response, GroupData.class);
    }

    public GroupData modifyGroup(String groupID, GroupData groupData) {
        Response response = groupClient.modifyGroup(groupID, groupData);
        return client.getEntity(response, GroupData.class);
    }

    public void removeGroup(String groupID) {
        Response response = groupClient.removeGroup(groupID);
        client.getEntity(response, Void.class);
    }

    public GroupMemberCollection findGroupMembers(
            String groupID,
            String filter,
            Integer start,
            Integer size) {
        Response response = groupClient.findGroupMembers(groupID, filter, start, size);
        return client.getEntity(response, GroupMemberCollection.class);
    }

    public GroupMemberData getGroupMember(String groupID, String memberID) {
        Response response = groupClient.getGroupMember(groupID, memberID);
        return client.getEntity(response, GroupMemberData.class);
    }

    public GroupMemberData addGroupMember(String groupID, String memberID) {
        GroupMemberData data = new GroupMemberData();
        data.setID(memberID);
        Response response = groupClient.addGroupMember(groupID, data);
        return client.getEntity(response, GroupMemberData.class);
    }

    public void removeGroupMember(String groupID, String memberID) {
        Response response = groupClient.removeGroupMember(groupID, memberID);
        client.getEntity(response, Void.class);
    }
}
