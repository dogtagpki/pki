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

package com.netscape.certsrv.user;

import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.StringTokenizer;

import javax.ws.rs.FormParam;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.CertIdAdapter;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="UserCert")
public class UserCertData {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(UserCertData.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(UserCertData.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    Integer version;
    CertId serialNumber;
    String issuerDN;
    String subjectDN;
    String prettyPrint;
    String encoded;

    Link link;

    @XmlAttribute(name="id")
    public String getID() {
        if (version == null && serialNumber == null && issuerDN == null && subjectDN == null) {
            return null;
        } else {
            return version + ";" + serialNumber + ";" + issuerDN + ";" + subjectDN;
        }
    }

    public void setID(String id) {
        StringTokenizer st = new StringTokenizer(id, ";");
        version = Integer.valueOf(st.nextToken());
        serialNumber = new CertId(st.nextToken());
        issuerDN = st.nextToken();
        subjectDN = st.nextToken();
    }

    @XmlElement(name="Version")
    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    @XmlElement(name="SerialNumber")
    @XmlJavaTypeAdapter(CertIdAdapter.class)
    public CertId getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(CertId serialNumber) {
        this.serialNumber = serialNumber;
    }

    @XmlElement(name="IssuerDN")
    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    @XmlElement(name="SubjectDN")
    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    @XmlElement(name="PrettyPrint")
    public String getPrettyPrint() {
        return prettyPrint;
    }

    public void setPrettyPrint(String prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    @FormParam(Constants.PR_USER_CERT)
    @XmlElement(name="Encoded")
    public String getEncoded() {
        return encoded;
    }

    public void setEncoded(String encoded) {
        this.encoded = encoded;
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
        result = prime * result + ((encoded == null) ? 0 : encoded.hashCode());
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((prettyPrint == null) ? 0 : prettyPrint.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
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
        UserCertData other = (UserCertData) obj;
        if (encoded == null) {
            if (other.encoded != null)
                return false;
        } else if (!encoded.equals(other.encoded))
            return false;
        if (issuerDN == null) {
            if (other.issuerDN != null)
                return false;
        } else if (!issuerDN.equals(other.issuerDN))
            return false;
        if (prettyPrint == null) {
            if (other.prettyPrint != null)
                return false;
        } else if (!prettyPrint.equals(other.prettyPrint))
            return false;
        if (serialNumber == null) {
            if (other.serialNumber != null)
                return false;
        } else if (!serialNumber.equals(other.serialNumber))
            return false;
        if (subjectDN == null) {
            if (other.subjectDN != null)
                return false;
        } else if (!subjectDN.equals(other.subjectDN))
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

    public static UserCertData valueOf(String string) throws Exception {
        try {
            return (UserCertData)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        StringWriter sw = new StringWriter();
        PrintWriter out = new PrintWriter(sw, true);

        out.println("-----BEGIN CERTIFICATE-----");
        out.println("MIIB/zCCAWgCCQCtpWH58pqsejANBgkqhkiG9w0BAQUFADBEMRQwEgYDVQQKDAtF");
        out.println("WEFNUExFLUNPTTEYMBYGCgmSJomT8ixkAQEMCHRlc3R1c2VyMRIwEAYDVQQDDAlU");
        out.println("ZXN0IFVzZXIwHhcNMTIwNTE0MTcxNzI3WhcNMTMwNTE0MTcxNzI3WjBEMRQwEgYD");
        out.println("VQQKDAtFWEFNUExFLUNPTTEYMBYGCgmSJomT8ixkAQEMCHRlc3R1c2VyMRIwEAYD");
        out.println("VQQDDAlUZXN0IFVzZXIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKmmiPJp");
        out.println("Agh/gPUAZjfgJ3a8QiHvpMzZ/hZy1FVP3+2sNhCkMv+D/I8Y7AsrbJGxxvD7bTDm");
        out.println("zQYtYx2ryGyOgY7KBRxEj/IrNVHIkJMYq5G/aIU4FAzpc6ntNSwUQBYUAamfK8U6");
        out.println("Wo4Cp6rLePXIDE6sfGn3VX6IeSJ8U2V+vwtzAgMBAAEwDQYJKoZIhvcNAQEFBQAD");
        out.println("gYEAY9bjcD/7Z+oX6gsJtX6Rd79E7X5IBdOdArYzHNE4vjdaQrZw6oCxrY8ffpKC");
        out.println("0T0q5PX9I7er+hx/sQjGPMrJDEN+vFBSNrZE7sTeLRgkyiqGvChSyuG05GtGzXO4");
        out.println("bFBr+Gwk2VF2wJvOhTXU2hN8sfkkd9clzIXuL8WCDhWk1bY=");
        out.println("-----END CERTIFICATE-----");

        UserCertData before = new UserCertData();
        before.setVersion(1);
        before.setSerialNumber(new CertId("12512514865863765114"));
        before.setIssuerDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setEncoded(sw.toString());

        String string = before.toString();
        System.out.println(string);

        UserCertData after = UserCertData.valueOf(string);
        System.out.println(before.equals(after));
    }
}
