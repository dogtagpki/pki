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

import java.io.StringReader;
import java.io.StringWriter;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.apache.commons.lang3.StringUtils;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.CertIdAdapter;
import com.netscape.certsrv.util.DateAdapter;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "CertData")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertData implements JSONSerializer {

    CertId serialNumber;
    String issuerDN;
    String subjectDN;
    String prettyPrint;
    String encoded;
    String pkcs7CertChain;
    String notBefore;
    String notAfter;
    String status;
    Date revokedOn;
    String revokedBy;
    Integer revocationReason;

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

    @XmlElement(name="RevokedOn")
    @XmlJavaTypeAdapter(DateAdapter.class)
    public Date getRevokedOn() {
        return revokedOn;
    }

    public void setRevokedOn(Date revokedOn) {
        this.revokedOn = revokedOn;
    }

    @XmlElement(name="RevokedBy")
    public String getRevokedBy() {
        return revokedBy;
    }

    public void setRevokedBy(String revokedBy) {
        this.revokedBy = revokedBy;
    }

    @XmlElement(name="RevocationReason")
    public Integer getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(Integer revocationReason) {
        this.revocationReason = revocationReason;
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
        result = prime * result + ((revokedOn == null) ? 0 : revokedOn.hashCode());
        result = prime * result + ((revokedBy == null) ? 0 : revokedBy.hashCode());
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
        if (revokedOn == null) {
            if (other.revokedOn != null)
                return false;
        } else if (!revokedOn.equals(other.revokedOn))
            return false;
        if (revokedBy == null) {
            if (other.revokedBy != null)
                return false;
        } else if (!revokedBy.equals(other.revokedBy))
            return false;
        return true;
    }

    public Element toDOM(Document document) {

        Element dataElement = document.createElement("CertData");

        if (serialNumber != null) {
            dataElement.setAttribute("id", serialNumber.toHexString());
        }

        if (issuerDN != null) {
            Element issuerDNElement = document.createElement("IssuerDN");
            issuerDNElement.appendChild(document.createTextNode(issuerDN));
            dataElement.appendChild(issuerDNElement);
        }

        if (subjectDN != null) {
            Element subjectDNElement = document.createElement("SubjectDN");
            subjectDNElement.appendChild(document.createTextNode(subjectDN));
            dataElement.appendChild(subjectDNElement);
        }

        if (prettyPrint != null) {
            Element prettyPrintElement = document.createElement("PrettyPrint");
            prettyPrintElement.appendChild(document.createTextNode(prettyPrint));
            dataElement.appendChild(prettyPrintElement);
        }

        if (encoded != null) {
            Element encodedElement = document.createElement("Encoded");
            encodedElement.appendChild(document.createTextNode(encoded));
            dataElement.appendChild(encodedElement);
        }

        if (pkcs7CertChain != null) {
            Element pkcs7CertChainElement = document.createElement("PKCS7CertChain");
            pkcs7CertChainElement.appendChild(document.createTextNode(pkcs7CertChain));
            dataElement.appendChild(pkcs7CertChainElement);
        }

        if (notBefore != null) {
            Element notBeforeElement = document.createElement("NotBefore");
            notBeforeElement.appendChild(document.createTextNode(notBefore));
            dataElement.appendChild(notBeforeElement);
        }

        if (notAfter != null) {
            Element notAfterElement = document.createElement("NotAfter");
            notAfterElement.appendChild(document.createTextNode(notAfter));
            dataElement.appendChild(notAfterElement);
        }

        if (status != null) {
            Element statusElement = document.createElement("Status");
            statusElement.appendChild(document.createTextNode(status));
            dataElement.appendChild(statusElement);
        }

        if (nonce != null) {
            Element nonceElement = document.createElement("Nonce");
            nonceElement.appendChild(document.createTextNode(Long.toString(nonce)));
            dataElement.appendChild(nonceElement);
        }

        if (revokedOn != null) {
            Element revokedOnElement = document.createElement("RevokedOn");
            revokedOnElement.appendChild(document.createTextNode(Long.toString(revokedOn.getTime())));
            dataElement.appendChild(revokedOnElement);
        }

        if (revokedBy != null) {
            Element revokedByElement = document.createElement("RevokedBy");
            revokedByElement.appendChild(document.createTextNode(revokedBy));
            dataElement.appendChild(revokedByElement);
        }

        if (revocationReason != null) {
            Element revocationReasonElement = document.createElement("RevocationReason");
            revocationReasonElement.appendChild(document.createTextNode(Integer.toString(revocationReason)));
            dataElement.appendChild(revocationReasonElement);
        }

        if (link != null) {
            Element linkElement = link.toDOM(document);
            dataElement.appendChild(linkElement);
        }

        return dataElement;
    }

    public static CertData fromDOM(Element dataElement) {

        CertData data = new CertData();

        String id = dataElement.getAttribute("id");
        data.setSerialNumber(StringUtils.isEmpty(id) ? null : new CertId(id));

        NodeList issuerDNList = dataElement.getElementsByTagName("IssuerDN");
        if (issuerDNList.getLength() > 0) {
            String value = issuerDNList.item(0).getTextContent();
            data.setIssuerDN(value);
        }

        NodeList subjectDNList = dataElement.getElementsByTagName("SubjectDN");
        if (subjectDNList.getLength() > 0) {
            String value = subjectDNList.item(0).getTextContent();
            data.setSubjectDN(value);
        }

        NodeList prettyPrintList = dataElement.getElementsByTagName("PrettyPrint");
        if (prettyPrintList.getLength() > 0) {
            String value = prettyPrintList.item(0).getTextContent();
            data.setPrettyPrint(value);
        }

        NodeList encodedList = dataElement.getElementsByTagName("Encoded");
        if (encodedList.getLength() > 0) {
            String value = encodedList.item(0).getTextContent();
            data.setEncoded(value);
        }

        NodeList pkcs7CertChainList = dataElement.getElementsByTagName("PKCS7CertChain");
        if (pkcs7CertChainList.getLength() > 0) {
            String value = pkcs7CertChainList.item(0).getTextContent();
            data.setPkcs7CertChain(value);
        }

        NodeList notBeforeList = dataElement.getElementsByTagName("NotBefore");
        if (notBeforeList.getLength() > 0) {
            String value = notBeforeList.item(0).getTextContent();
            data.setNotBefore(value);
        }

        NodeList notAfterList = dataElement.getElementsByTagName("NotAfter");
        if (notAfterList.getLength() > 0) {
            String value = notAfterList.item(0).getTextContent();
            data.setNotAfter(value);
        }

        NodeList statusList = dataElement.getElementsByTagName("Status");
        if (statusList.getLength() > 0) {
            String value = statusList.item(0).getTextContent();
            data.setStatus(value);
        }

        NodeList nonceList = dataElement.getElementsByTagName("Nonce");
        if (nonceList.getLength() > 0) {
            String value = nonceList.item(0).getTextContent();
            data.setNonce(Long.parseLong(value));
        }

        NodeList revokedOnList = dataElement.getElementsByTagName("RevokedOn");
        if (revokedOnList.getLength() > 0) {
            String value = revokedOnList.item(0).getTextContent();
            data.setRevokedOn(new Date(Long.parseLong(value)));
        }

        NodeList revokedByList = dataElement.getElementsByTagName("RevokedBy");
        if (revokedByList.getLength() > 0) {
            String value = revokedByList.item(0).getTextContent();
            data.setRevokedBy(value);
        }

        NodeList revocationReasonList = dataElement.getElementsByTagName("RevocationReason");
        if (revocationReasonList.getLength() > 0) {
            String value = revocationReasonList.item(0).getTextContent();
            data.setRevocationReason(Integer.parseInt(value));
        }

        NodeList linkList = dataElement.getElementsByTagName("Link");
        if (linkList.getLength() > 0) {
           Element linkElement = (Element) linkList.item(0);
           Link link = Link.fromDOM(linkElement);
           data.setLink(link);
        }

        return data;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(CertData.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static CertData fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(CertData.class).createUnmarshaller();
        return (CertData) unmarshaller.unmarshal(new StringReader(xml));
    }

    public static CertData fromCertChain(PKCS7 pkcs7) throws Exception {

        X509Certificate[] certs = pkcs7.getCertificates();
        certs = Cert.sortCertificateChain(certs);

        X509Certificate cert = certs[certs.length - 1];

        CertData data = new CertData();

        data.setSerialNumber(new CertId(cert.getSerialNumber()));

        Principal issuerDN = cert.getIssuerDN();
        if (issuerDN != null) data.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN != null) data.setSubjectDN(subjectDN.toString());

        Date notBefore = cert.getNotBefore();
        if (notBefore != null) data.setNotBefore(notBefore.toString());

        Date notAfter = cert.getNotAfter();
        if (notAfter != null) data.setNotAfter(notAfter.toString());

        String b64 = Cert.HEADER + "\n" + Utils.base64encodeMultiLine(cert.getEncoded()) + Cert.FOOTER + "\n";
        data.setEncoded(b64);

        byte[] pkcs7bytes = pkcs7.getBytes();
        String pkcs7str = Utils.base64encodeSingleLine(pkcs7bytes);
        data.setPkcs7CertChain(pkcs7str);

        return data;
    }

}
