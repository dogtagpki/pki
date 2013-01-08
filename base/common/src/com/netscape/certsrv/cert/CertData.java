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
package com.netscape.certsrv.cert;

import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;

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

/**
 * @author alee
 *
 */
@XmlRootElement(name = "CertData")
public class CertData {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(CertData.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(CertData.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    CertId serialNumber;
    String issuerDN;
    String subjectDN;
    String prettyPrint;
    String encoded;
    String pkcs7CertChain;
    String notBefore;
    String notAfter;
    String status;
    Long nonce;

    Link link;

    @XmlAttribute(name="id")
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

    @XmlElement(name="Encoded")
    public String getEncoded() {
        return encoded;
    }

    public void setEncoded(String encoded) {
        this.encoded = encoded;
    }

    @XmlElement(name="PKCS7CertChain")
    public void setPkcs7CertChain(String chain) {
        this.pkcs7CertChain = chain;
    }

    public String getPkcs7CertChain() {
        return pkcs7CertChain;
    }

    @XmlElement(name="NotBefore")
    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    @XmlElement(name="NotAfter")
    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    @XmlElement(name="Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @XmlElement(name="Nonce")
    public Long getNonce() {
        return nonce;
    }

    public void setNonce(Long nonce) {
        this.nonce = nonce;
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
        result = prime * result + ((nonce == null) ? 0 : nonce.hashCode());
        result = prime * result + ((notAfter == null) ? 0 : notAfter.hashCode());
        result = prime * result + ((notBefore == null) ? 0 : notBefore.hashCode());
        result = prime * result + ((pkcs7CertChain == null) ? 0 : pkcs7CertChain.hashCode());
        result = prime * result + ((prettyPrint == null) ? 0 : prettyPrint.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
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
        CertData other = (CertData) obj;
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
        if (nonce == null) {
            if (other.nonce != null)
                return false;
        } else if (!nonce.equals(other.nonce))
            return false;
        if (notAfter == null) {
            if (other.notAfter != null)
                return false;
        } else if (!notAfter.equals(other.notAfter))
            return false;
        if (notBefore == null) {
            if (other.notBefore != null)
                return false;
        } else if (!notBefore.equals(other.notBefore))
            return false;
        if (pkcs7CertChain == null) {
            if (other.pkcs7CertChain != null)
                return false;
        } else if (!pkcs7CertChain.equals(other.pkcs7CertChain))
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

    public static CertData valueOf(String string) throws Exception {
        try {
            return (CertData)unmarshaller.unmarshal(new StringReader(string));
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

        CertData before = new CertData();
        before.setSerialNumber(new CertId("12512514865863765114"));
        before.setIssuerDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setSubjectDN("CN=Test User,UID=testuser,O=EXAMPLE-COM");
        before.setEncoded(sw.toString());
        before.setNonce(12345l);

        String string = before.toString();
        System.out.println(string);

        CertData after = CertData.valueOf(string);
        System.out.println(before.equals(after));
    }
}
