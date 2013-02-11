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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.user;

import java.util.ArrayList;
import java.util.Collection;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.jboss.resteasy.plugins.providers.atom.Link;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="UserMemberships")
public class UserMembershipCollection {

    Collection<UserMembershipData> memberships = new ArrayList<UserMembershipData>();
    Collection<Link> links = new ArrayList<Link>();

    @XmlElement(name="Membership")
    public Collection<UserMembershipData> getMemberships() {
        return memberships;
    }

    public void setMemberships(Collection<UserMembershipData> members) {
        this.memberships = members;
    }

    public void addMembership(UserMembershipData member) {
        memberships.add(member);
    }

    @XmlElement(name="Link")
    public Collection<Link> getLinks() {
        return links;
    }

    public void setLink(Collection<Link> links) {
        this.links = links;
    }

    public void addLink(Link link) {
        links.add(link);
    }

    public static void main(String args[]) throws Exception {

        UserMembershipCollection response = new UserMembershipCollection();

        UserMembershipData membership1 = new UserMembershipData();
        membership1.setID("Group 1");
        membership1.setUserID("User 1");
        response.addMembership(membership1);

        UserMembershipData membership2 = new UserMembershipData();
        membership2.setID("Group 2");
        membership2.setUserID("User 1");
        response.addMembership(membership2);

        JAXBContext context = JAXBContext.newInstance(UserMembershipCollection.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(response, System.out);
    }
}
