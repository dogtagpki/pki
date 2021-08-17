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
import java.util.Map;
import java.util.TreeSet;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="Account")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class Account extends ResourceMessage {

    String id;
    String fullName;
    String email;
    Collection<String> roles = new TreeSet<>();

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

    public void addRole(String role) {
        roles.add(role);
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

    public Element toDOM(Document document) {

        Element accountElement = document.createElement("Account");
        accountElement.setAttribute("id", id);

        // The original XML mapping always creates <Attributes/>.
        Element attributesElement = document.createElement("Attributes");
        accountElement.appendChild(attributesElement);

        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            Element attributeElement = document.createElement("Attribute");
            attributeElement.setAttribute("name", attribute.getKey());
            attributeElement.appendChild(document.createTextNode(attribute.getValue()));
            attributesElement.appendChild(attributeElement);
        }

        if (className != null) {
            Element classNameElement = document.createElement("ClassName");
            classNameElement.appendChild(document.createTextNode(className));
            accountElement.appendChild(classNameElement);
        }

        if (fullName != null) {
            Element fullNameElement = document.createElement("FullName");
            fullNameElement.appendChild(document.createTextNode(fullName));
            accountElement.appendChild(fullNameElement);
        }

        if (email != null) {
            Element emailElement = document.createElement("Email");
            emailElement.appendChild(document.createTextNode(email));
            accountElement.appendChild(emailElement);
        }

        if (!roles.isEmpty()) {
            Element rolesElement = document.createElement("Roles");
            accountElement.appendChild(rolesElement);

            for (String role : roles) {
                Element roleElement = document.createElement("Role");
                roleElement.appendChild(document.createTextNode(role));
                rolesElement.appendChild(roleElement);
            }
        }

        return accountElement;
    }

    public static Account fromDOM(Element accountElement) {

        Account account = new Account();

        String id = accountElement.getAttribute("id");
        account.setID(id);

        NodeList classNameList = accountElement.getElementsByTagName("ClassName");
        if (classNameList.getLength() > 0) {
            String value = classNameList.item(0).getTextContent();
            account.setClassName(value);
        }

        NodeList attributeList = accountElement.getElementsByTagName("Attribute");
        int attributeCount = attributeList.getLength();
        if (attributeCount > 0) {
            for (int i=0; i<attributeCount; i++) {
               Element attributeElement = (Element) attributeList.item(i);
               String name = attributeElement.getAttribute("name");
               String value = attributeElement.getTextContent();
               account.setAttribute(name, value);
            }
        }

        NodeList fullNameList = accountElement.getElementsByTagName("FullName");
        if (fullNameList.getLength() > 0) {
            String value = fullNameList.item(0).getTextContent();
            account.setFullName(value);
        }

        NodeList emailList = accountElement.getElementsByTagName("Email");
        if (emailList.getLength() > 0) {
            String email = emailList.item(0).getTextContent();
            account.setEmail(email);
        }

        NodeList roleList = accountElement.getElementsByTagName("Role");
        int length = roleList.getLength();
        if (length > 0) {
            for (int i=0; i<length; i++) {
               String role = roleList.item(i).getTextContent();
               account.addRole(role);
            }
        }

        return account;
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

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static class RolesAdapter extends XmlAdapter<RoleList, Collection<String>> {

        @Override
        public RoleList marshal(Collection<String> roles) {
            RoleList list = new RoleList();
            list.roles = roles.toArray(new String[roles.size()]);
            return list;
        }

        @Override
        public Collection<String> unmarshal(RoleList list) {
            Collection<String> roles = new TreeSet<>();
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

}
