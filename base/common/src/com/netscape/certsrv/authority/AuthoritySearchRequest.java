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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.authority;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name="AuthoritySearchRequest")
public class AuthoritySearchRequest {

    String id;
    String parentID;
    String dn;
    String issuerDN;

    public AuthoritySearchRequest() {
    }

    @XmlElement(name="ID")
    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    @XmlElement(name="ParentID")
    public String getParentID() {
        return parentID;
    }

    public void setParentID(String parentID) {
        this.parentID = parentID;
    }

    @XmlElement(name="DN")
    public String getDN() {
        return dn;
    }

    public void setDN(String dn) {
        this.dn = dn;
    }

    @XmlElement(name="IssuerDN")
    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((dn == null) ? 0 : dn.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((parentID == null) ? 0 : parentID.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AuthoritySearchRequest other = (AuthoritySearchRequest) obj;
        if (dn == null) {
            if (other.dn != null)
                return false;
        } else if (!dn.equals(other.dn))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (issuerDN == null) {
            if (other.issuerDN != null)
                return false;
        } else if (!issuerDN.equals(other.issuerDN))
            return false;
        if (parentID == null) {
            if (other.parentID != null)
                return false;
        } else if (!parentID.equals(other.parentID))
            return false;
        return true;
    }

    public String toString() {
        try {
            Marshaller marshaller = JAXBContext.newInstance(AuthoritySearchRequest.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            StringWriter writer = new StringWriter();
            marshaller.marshal(this, writer);
            return writer.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static AuthoritySearchRequest valueOf(String string) throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(AuthoritySearchRequest.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        return (AuthoritySearchRequest) unmarshaller.unmarshal(new StringReader(string));
    }

    public static void main(String args[]) throws Exception {

        AuthoritySearchRequest before = new AuthoritySearchRequest();
        before.setID("12345");
        before.setParentID("12345");
        before.setDN("CN=SubCA");
        before.setIssuerDN("CN=RootCA");

        String string = before.toString();
        System.out.println(string);

        AuthoritySearchRequest after = AuthoritySearchRequest.valueOf(string);
        System.out.println(before.equals(after));
    }
}
