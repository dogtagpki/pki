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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.account;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.TreeSet;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="Account")
public class Account extends ResourceMessage {

    String id;
    String fullName;
    String email;
    Collection<String> roles = new TreeSet<String>();

    @XmlAttribute(name="id")
    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    @XmlElement(name="FullName")
    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    @XmlElement(name="Email")
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @XmlElement(name="Roles")
    @XmlJavaTypeAdapter(RolesAdapter.class)
    public Collection<String> getRoles() {
        return roles;
    }

    public void setRoles(Collection<String> roles) {
        this.roles.clear();
        this.roles.addAll(roles);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((email == null) ? 0 : email.hashCode());
        result = prime * result + ((fullName == null) ? 0 : fullName.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((roles == null) ? 0 : roles.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        Account other = (Account) obj;
        if (email == null) {
            if (other.email != null)
                return false;
        } else if (!email.equals(other.email))
            return false;
        if (fullName == null) {
            if (other.fullName != null)
                return false;
        } else if (!fullName.equals(other.fullName))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (roles == null) {
            if (other.roles != null)
                return false;
        } else if (!roles.equals(other.roles))
            return false;
        return true;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(Account.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static Account fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(Account.class).createUnmarshaller();
        return (Account) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static Account fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, Account.class);
    }

    public static Account valueOf(String xml) throws Exception {
        return fromXML(xml);
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static class RolesAdapter extends XmlAdapter<RoleList, Collection<String>> {

        public RoleList marshal(Collection<String> roles) {
            RoleList list = new RoleList();
            list.roles = roles.toArray(new String[roles.size()]);
            return list;
        }

        public Collection<String> unmarshal(RoleList list) {
            Collection<String> roles = new TreeSet<String>();
            if (list.roles != null) {
                roles.addAll(Arrays.asList(list.roles));
            }
            return roles;
        }
    }

    public static class RoleList {

        @XmlElement(name="Role")
        public String[] roles;
    }

    public static void main(String args[]) throws Exception {

        Account before = new Account();
        before.setID("testuser");
        before.setFullName("Test User");
        before.setEmail("testuser@example.com");
        before.setRoles(Arrays.asList("admin", "agent"));

        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        Account afterXML = Account.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        System.out.println(before.equals(afterXML));

        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        Account afterJSON = Account.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        System.out.println(before.equals(afterJSON));
    }
}
