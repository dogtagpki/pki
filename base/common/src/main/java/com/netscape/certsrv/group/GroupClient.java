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

import java.util.HashMap;
import java.util.Map;

import org.apache.http.HttpEntity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

/**
 * @author Endi S. Dewata
 */
public class GroupClient extends Client {

    public GroupClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "admin/groups");
    }

    public GroupClient(SubsystemClient subsystemClient) throws Exception {
        this(subsystemClient.client, subsystemClient.getName());
    }

    public GroupCollection findGroups(String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, GroupCollection.class);
    }

    public GroupData getGroup(String groupID) throws Exception {
        return get(groupID, GroupData.class);
    }

    public GroupData addGroup(GroupData groupData) throws Exception {
        HttpEntity entity = client.entity(groupData);
        return post(null, null, entity, GroupData.class);
    }

    public GroupData modifyGroup(String groupID, GroupData groupData) throws Exception {
        HttpEntity entity = client.entity(groupData);
        return patch(groupID, null, entity, GroupData.class);
    }

    public void removeGroup(String groupID) throws Exception {
        delete(groupID, Void.class);
    }

    public GroupMemberCollection findGroupMembers(
            String groupID,
            String filter,
            Integer start,
            Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(groupID + "/members", params, GroupMemberCollection.class);
    }

    public GroupMemberData getGroupMember(String groupID, String memberID) throws Exception {
        return get(groupID + "/members/" + memberID, GroupMemberData.class);
    }

    public GroupMemberData addGroupMember(String groupID, String memberID) throws Exception {
        GroupMemberData data = new GroupMemberData();
        data.setID(memberID);
        HttpEntity entity = client.entity(data);
        return post(groupID + "/members", null, entity, GroupMemberData.class);
    }

    public void removeGroupMember(String groupID, String memberID) throws Exception {
        delete(groupID + "/members/" + memberID, Void.class);
    }
}
