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

package com.netscape.certsrv.group;

import java.util.Collection;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.DataCollection;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="GroupMembers")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class GroupMemberCollection extends DataCollection<GroupMemberData> {

    @XmlElement(name="Member")
    public Collection<GroupMemberData> getEntries() {
        return super.getEntries();
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static GroupMemberCollection fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, GroupMemberCollection.class);
    }

    public static void main(String args[]) throws Exception {

        GroupMemberCollection before = new GroupMemberCollection();

        GroupMemberData member1 = new GroupMemberData();
        member1.setID("User 1");
        member1.setGroupID("Group 1");
        before.addEntry(member1);

        GroupMemberData member2 = new GroupMemberData();
        member2.setID("User 2");
        member2.setGroupID("Group 1");
        before.addEntry(member2);

        before.setTotal(2);

        String json = before.toJSON();
        System.out.println("Before: " + json);

        GroupMemberCollection afterJSON = GroupMemberCollection.fromJSON(json);
        System.out.println("After: " + afterJSON.toJSON());

        System.out.println(before.equals(afterJSON));
    }
}
