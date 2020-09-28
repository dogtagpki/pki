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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.base.DataCollection;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="GroupMembers")
public class GroupMemberCollection extends DataCollection<GroupMemberData> {

    @XmlElement(name="Member")
    public Collection<GroupMemberData> getEntries() {
        return super.getEntries();
    }

    public static void main(String args[]) throws Exception {

        GroupMemberCollection response = new GroupMemberCollection();

        GroupMemberData member1 = new GroupMemberData();
        member1.setID("User 1");
        member1.setGroupID("Group 1");
        response.addEntry(member1);

        GroupMemberData member2 = new GroupMemberData();
        member2.setID("User 2");
        member2.setGroupID("Group 1");
        response.addEntry(member2);

        JAXBContext context = JAXBContext.newInstance(GroupMemberCollection.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(response, System.out);
    }
}
