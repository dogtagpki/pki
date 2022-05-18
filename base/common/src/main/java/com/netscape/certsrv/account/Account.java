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
import java.util.Collection;
import java.util.TreeSet;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.base.RESTMessage;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class Account extends RESTMessage {

    String id;
    @JsonProperty("FullName")
    String fullName;
    @JsonProperty("Email")
    String email;
    @JsonProperty("Roles")
    Collection<String> roles = new TreeSet<>();

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

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

    @Override
    public Element toDOM(Document document) {

        Element accountElement = document.createElement("Account");
        accountElement.setAttribute("id", id);

        toDOM(document, accountElement);

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

        fromDOM(accountElement, account);

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

    @Override
    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element accountElement = toDOM(document);
        document.appendChild(accountElement);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);
        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);

        return sw.toString();
    }

    public static Account fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element accountElement = document.getDocumentElement();
        return fromDOM(accountElement);
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
