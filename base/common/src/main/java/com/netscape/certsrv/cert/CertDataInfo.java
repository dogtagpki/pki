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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertDataInfo implements JSONSerializer {

    CertId id;
    String subjectDN;
    String issuerDN;
    String status;
    String type;
    Integer version;
    String keyAlgorithmOID;
    Integer keyLength;
    Date notValidBefore;
    Date notValidAfter;
    Date issuedOn;
    String issuedBy;
    Date revokedOn;
    String revokedBy;

    Link link;

    public CertId getID() {
        return id;
    }

    public void setID(CertId id) {
        this.id = id;
    }

    @JsonProperty("SubjectDN")
    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    @JsonProperty("IssuerDN")
    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    @JsonProperty("Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @JsonProperty("Type")
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @JsonProperty("Version")
    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    @JsonProperty("KeyAlgorithmOID")
    public String getKeyAlgorithmOID() {
        return keyAlgorithmOID;
    }

    public void setKeyAlgorithmOID(String keyAlgorithmOID) {
        this.keyAlgorithmOID = keyAlgorithmOID;
    }

    @JsonProperty("KeyLength")
    public Integer getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    @JsonProperty("NotValidBefore")
    public Date getNotValidBefore() {
        return notValidBefore;
    }

    public void setNotValidBefore(Date notValidBefore) {
        this.notValidBefore = notValidBefore;
    }

    @JsonProperty("NotValidAfter")
    public Date getNotValidAfter() {
        return notValidAfter;
    }

    public void setNotValidAfter(Date notValidAfter) {
        this.notValidAfter = notValidAfter;
    }

    @JsonProperty("IssuedOn")
    public Date getIssuedOn() {
        return issuedOn;
    }

    public void setIssuedOn(Date issuedOn) {
        this.issuedOn = issuedOn;
    }

    @JsonProperty("IssuedBy")
    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    @JsonProperty("RevokedOn")
    public Date getRevokedOn() {
        return revokedOn;
    }

    public void setRevokedOn(Date revokedOn) {
        this.revokedOn = revokedOn;
    }

    @JsonProperty("RevokedBy")
    public String getRevokedBy() {
        return revokedBy;
    }

    public void setRevokedBy(String revokedBy) {
        this.revokedBy = revokedBy;
    }

    @JsonProperty("Link")
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
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
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
        if (issuerDN == null) {
            if (other.issuerDN != null) return false;
        } else if (!issuerDN.equals(other.issuerDN)) {
            return false;
        }
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

        Element infoElement = document.createElement("CertDataInfo");

        if (id != null) {
            infoElement.setAttribute("id", id.toHexString());
        }

        if (subjectDN != null) {
            Element subjectDNElement = document.createElement("SubjectDN");
            subjectDNElement.appendChild(document.createTextNode(subjectDN));
            infoElement.appendChild(subjectDNElement);
        }

        if (issuerDN != null) {
            Element issuerDNElement = document.createElement("IssuerDN");
            issuerDNElement.appendChild(document.createTextNode(issuerDN));
            infoElement.appendChild(issuerDNElement);
        }

        if (status != null) {
            Element statusElement = document.createElement("Status");
            statusElement.appendChild(document.createTextNode(status));
            infoElement.appendChild(statusElement);
        }

        if (type != null) {
            Element typeElement = document.createElement("Type");
            typeElement.appendChild(document.createTextNode(type));
            infoElement.appendChild(typeElement);
        }

        if (version != null) {
            Element versionElement = document.createElement("Version");
            versionElement.appendChild(document.createTextNode(Integer.toString(version)));
            infoElement.appendChild(versionElement);
        }

        if (keyAlgorithmOID != null) {
            Element keyAlgorithmOIDElement = document.createElement("KeyAlgorithmOID");
            keyAlgorithmOIDElement.appendChild(document.createTextNode(keyAlgorithmOID));
            infoElement.appendChild(keyAlgorithmOIDElement);
        }

        if (keyLength != null) {
            Element keyLengthElement = document.createElement("KeyLength");
            keyLengthElement.appendChild(document.createTextNode(Integer.toString(keyLength)));
            infoElement.appendChild(keyLengthElement);
        }

        if (notValidBefore != null) {
            Element notValidBeforeElement = document.createElement("NotValidBefore");
            notValidBeforeElement.appendChild(document.createTextNode(Long.toString(notValidBefore.getTime())));
            infoElement.appendChild(notValidBeforeElement);
        }

        if (notValidAfter != null) {
            Element notValidAfterElement = document.createElement("NotValidAfter");
            notValidAfterElement.appendChild(document.createTextNode(Long.toString(notValidAfter.getTime())));
            infoElement.appendChild(notValidAfterElement);
        }

        if (issuedOn != null) {
            Element issuedOnElement = document.createElement("IssuedOn");
            issuedOnElement.appendChild(document.createTextNode(Long.toString(issuedOn.getTime())));
            infoElement.appendChild(issuedOnElement);
        }

        if (issuedBy != null) {
            Element issuedByElement = document.createElement("IssuedBy");
            issuedByElement.appendChild(document.createTextNode(issuedBy));
            infoElement.appendChild(issuedByElement);
        }

        if (revokedOn != null) {
            Element revokedOnElement = document.createElement("RevokedOn");
            revokedOnElement.appendChild(document.createTextNode(Long.toString(revokedOn.getTime())));
            infoElement.appendChild(revokedOnElement);
        }

        if (revokedBy != null) {
            Element revokedByElement = document.createElement("RevokedBy");
            revokedByElement.appendChild(document.createTextNode(revokedBy));
            infoElement.appendChild(revokedByElement);
        }

        if (link != null) {
            Element linkElement = link.toDOM(document);
            infoElement.appendChild(linkElement);
        }

        return infoElement;
    }

    public static CertDataInfo fromDOM(Element infoElement) {

        CertDataInfo info = new CertDataInfo();

        String id = infoElement.getAttribute("id");
        info.setID(StringUtils.isEmpty(id) ? null : new CertId(id));

        NodeList subjectDNList = infoElement.getElementsByTagName("SubjectDN");
        if (subjectDNList.getLength() > 0) {
            String value = subjectDNList.item(0).getTextContent();
            info.setSubjectDN(value);
        }

        NodeList issuerDNList = infoElement.getElementsByTagName("IssuerDN");
        if (issuerDNList.getLength() > 0) {
            String value = issuerDNList.item(0).getTextContent();
            info.setIssuerDN(value);
        }

        NodeList statusList = infoElement.getElementsByTagName("Status");
        if (statusList.getLength() > 0) {
            String value = statusList.item(0).getTextContent();
            info.setStatus(value);
        }

        NodeList typeList = infoElement.getElementsByTagName("Type");
        if (typeList.getLength() > 0) {
            String value = typeList.item(0).getTextContent();
            info.setType(value);
        }

        NodeList versionList = infoElement.getElementsByTagName("Version");
        if (versionList.getLength() > 0) {
            String value = versionList.item(0).getTextContent();
            info.setVersion(Integer.parseInt(value));
        }

        NodeList keyAlgorithmOIDList = infoElement.getElementsByTagName("KeyAlgorithmOID");
        if (keyAlgorithmOIDList.getLength() > 0) {
            String value = keyAlgorithmOIDList.item(0).getTextContent();
            info.setKeyAlgorithmOID(value);
        }

        NodeList keyLengthList = infoElement.getElementsByTagName("KeyLength");
        if (keyLengthList.getLength() > 0) {
            String value = keyLengthList.item(0).getTextContent();
            info.setKeyLength(Integer.parseInt(value));
        }

        NodeList notValidBeforeList = infoElement.getElementsByTagName("NotValidBefore");
        if (notValidBeforeList.getLength() > 0) {
            String value = notValidBeforeList.item(0).getTextContent();
            info.setNotValidBefore(new Date(Long.parseLong(value)));
        }

        NodeList notValidAfterList = infoElement.getElementsByTagName("NotValidAfter");
        if (notValidAfterList.getLength() > 0) {
            String value = notValidAfterList.item(0).getTextContent();
            info.setNotValidAfter(new Date(Long.parseLong(value)));
        }

        NodeList issuedOnList = infoElement.getElementsByTagName("IssuedOn");
        if (issuedOnList.getLength() > 0) {
            String value = issuedOnList.item(0).getTextContent();
            info.setIssuedOn(new Date(Long.parseLong(value)));
        }

        NodeList issuedByList = infoElement.getElementsByTagName("IssuedBy");
        if (issuedByList.getLength() > 0) {
            String value = issuedByList.item(0).getTextContent();
            info.setIssuedBy(value);
        }

        NodeList revokedOnList = infoElement.getElementsByTagName("RevokedOn");
        if (revokedOnList.getLength() > 0) {
            String value = revokedOnList.item(0).getTextContent();
            info.setRevokedOn(new Date(Long.parseLong(value)));
        }

        NodeList revokedByList = infoElement.getElementsByTagName("RevokedBy");
        if (revokedByList.getLength() > 0) {
            String value = revokedByList.item(0).getTextContent();
            info.setRevokedBy(value);
        }

        NodeList linkList = infoElement.getElementsByTagName("Link");
        if (linkList.getLength() > 0) {
            Element linkElement = (Element) linkList.item(0);
            Link link = Link.fromDOM(linkElement);
            info.setLink(link);
        }

        return info;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element infoElement = toDOM(document);
        document.appendChild(infoElement);

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

    public static CertDataInfo fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element infoElement = document.getDocumentElement();
        return fromDOM(infoElement);
    }
}
