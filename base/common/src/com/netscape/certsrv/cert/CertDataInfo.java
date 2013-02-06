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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
/**
 *
 */
package com.netscape.certsrv.cert;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Date;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.CertIdAdapter;
import com.netscape.certsrv.util.DateAdapter;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "CertDataInfo")
public class CertDataInfo {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            JAXBContext context = JAXBContext.newInstance(CertDataInfo.class);
            marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = context.createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    CertId id;
    String subjectDN;
    String status;
    String type;
    Integer version;
    String keyAlgorithmOID;
    Integer keyLength;
    Date notValidBefore;
    Date notValidAfter;
    Date issuedOn;
    String issuedBy;

    Link link;

    @XmlAttribute(name="id")
    @XmlJavaTypeAdapter(CertIdAdapter.class)
    public CertId getID() {
        return id;
    }

    public void setID(CertId id) {
        this.id = id;
    }

    @XmlElement(name="SubjectDN")
    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    @XmlElement(name="Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @XmlElement(name="Type")
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @XmlElement(name="Version")
    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    @XmlElement(name="KeyAlgorithmOID")
    public String getKeyAlgorithmOID() {
        return keyAlgorithmOID;
    }

    public void setKeyAlgorithmOID(String keyAlgorithmOID) {
        this.keyAlgorithmOID = keyAlgorithmOID;
    }

    @XmlElement(name="KeyLength")
    public Integer getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    @XmlElement(name="NotValidBefore")
    @XmlJavaTypeAdapter(DateAdapter.class)
    public Date getNotValidBefore() {
        return notValidBefore;
    }

    public void setNotValidBefore(Date notValidBefore) {
        this.notValidBefore = notValidBefore;
    }

    @XmlElement(name="NotValidAfter")
    @XmlJavaTypeAdapter(DateAdapter.class)
    public Date getNotValidAfter() {
        return notValidAfter;
    }

    public void setNotValidAfter(Date notValidAfter) {
        this.notValidAfter = notValidAfter;
    }

    @XmlElement(name="IssuedOn")
    @XmlJavaTypeAdapter(DateAdapter.class)
    public Date getIssuedOn() {
        return issuedOn;
    }

    public void setIssuedOn(Date issuedOn) {
        this.issuedOn = issuedOn;
    }

    @XmlElement(name="IssuedBy")
    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    @XmlElement(name="Link")
    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((issuedBy == null) ? 0 : issuedBy.hashCode());
        result = prime * result + ((issuedOn == null) ? 0 : issuedOn.hashCode());
        result = prime * result + ((keyAlgorithmOID == null) ? 0 : keyAlgorithmOID.hashCode());
        result = prime * result + ((keyLength == null) ? 0 : keyLength.hashCode());
        result = prime * result + ((link == null) ? 0 : link.hashCode());
        result = prime * result + ((notValidAfter == null) ? 0 : notValidAfter.hashCode());
        result = prime * result + ((notValidBefore == null) ? 0 : notValidBefore.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
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
        CertDataInfo other = (CertDataInfo) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (issuedBy == null) {
            if (other.issuedBy != null)
                return false;
        } else if (!issuedBy.equals(other.issuedBy))
            return false;
        if (issuedOn == null) {
            if (other.issuedOn != null)
                return false;
        } else if (!issuedOn.equals(other.issuedOn))
            return false;
        if (keyAlgorithmOID == null) {
            if (other.keyAlgorithmOID != null)
                return false;
        } else if (!keyAlgorithmOID.equals(other.keyAlgorithmOID))
            return false;
        if (keyLength == null) {
            if (other.keyLength != null)
                return false;
        } else if (!keyLength.equals(other.keyLength))
            return false;
        if (link == null) {
            if (other.link != null)
                return false;
        } else if (!link.equals(other.link))
            return false;
        if (notValidAfter == null) {
            if (other.notValidAfter != null)
                return false;
        } else if (!notValidAfter.equals(other.notValidAfter))
            return false;
        if (notValidBefore == null) {
            if (other.notValidBefore != null)
                return false;
        } else if (!notValidBefore.equals(other.notValidBefore))
            return false;
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        if (subjectDN == null) {
            if (other.subjectDN != null)
                return false;
        } else if (!subjectDN.equals(other.subjectDN))
            return false;
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type))
            return false;
        if (version == null) {
            if (other.version != null)
                return false;
        } else if (!version.equals(other.version))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static CertDataInfo valueOf(String string) throws Exception {
        try {
            return (CertDataInfo)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        CertDataInfo before = new CertDataInfo();
        before.setID(new CertId("12512514865863765114"));
        before.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setStatus("VALID");

        String string = before.toString();
        System.out.println(string);

        CertDataInfo after = CertDataInfo.valueOf(string);

        System.out.println(before.equals(after));
    }
}
