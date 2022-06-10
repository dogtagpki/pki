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
import java.util.Date;

import javax.xml.XMLConstants;
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
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRevokeRequest implements JSONSerializer {

    String reason;
    Date invalidityDate;
    String comments;
    String encoded;
    Long nonce;

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public Date getInvalidityDate() {
        return invalidityDate;
    }

    public void setInvalidityDate(Date invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    public String getComments() {
        return comments;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    public String getEncoded() {
        return encoded;
    }

    public void setEncoded(String encoded) {
        this.encoded = encoded;
    }

    public Long getNonce() {
        return nonce;
    }

    public void setNonce(Long nonce) {
        this.nonce = nonce;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((comments == null) ? 0 : comments.hashCode());
        result = prime * result + ((encoded == null) ? 0 : encoded.hashCode());
        result = prime * result + ((invalidityDate == null) ? 0 : invalidityDate.hashCode());
        result = prime * result + ((nonce == null) ? 0 : nonce.hashCode());
        result = prime * result + ((reason == null) ? 0 : reason.hashCode());
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
        CertRevokeRequest other = (CertRevokeRequest) obj;
        if (comments == null) {
            if (other.comments != null)
                return false;
        } else if (!comments.equals(other.comments))
            return false;
        if (encoded == null) {
            if (other.encoded != null)
                return false;
        } else if (!encoded.equals(other.encoded))
            return false;
        if (invalidityDate == null) {
            if (other.invalidityDate != null)
                return false;
        } else if (!invalidityDate.equals(other.invalidityDate))
            return false;
        if (nonce == null) {
            if (other.nonce != null)
                return false;
        } else if (!nonce.equals(other.nonce))
            return false;
        if (reason == null) {
            if (other.reason != null)
                return false;
        } else if (!reason.equals(other.reason))
            return false;
        return true;
    }

    public Element toDOM(Document document) {

        Element requestElement = document.createElement("CertRevokeRequest");

        if (reason != null) {
            Element reasonElement = document.createElement("Reason");
            reasonElement.appendChild(document.createTextNode(reason));
            requestElement.appendChild(reasonElement);
        }

        if (invalidityDate != null) {
            Element invalidityDateElement = document.createElement("InvalidityDate");
            invalidityDateElement.appendChild(document.createTextNode(Long.toString(invalidityDate.getTime())));
            requestElement.appendChild(invalidityDateElement);
        }

        if (comments != null) {
            Element commentsElement = document.createElement("Comments");
            commentsElement.appendChild(document.createTextNode(comments));
            requestElement.appendChild(commentsElement);
        }

        if (encoded != null) {
            Element encodedElement = document.createElement("Encoded");
            encodedElement.appendChild(document.createTextNode(encoded));
            requestElement.appendChild(encodedElement);
        }

        if (nonce != null) {
            Element nonceElement = document.createElement("Nonce");
            nonceElement.appendChild(document.createTextNode(Long.toString(nonce)));
            requestElement.appendChild(nonceElement);
        }

        return requestElement;
    }

    public static CertRevokeRequest fromDOM(Element dataElement) {

        CertRevokeRequest request = new CertRevokeRequest();

        NodeList reasonList = dataElement.getElementsByTagName("Reason");
        if (reasonList.getLength() > 0) {
            String value = reasonList.item(0).getTextContent();
            request.setReason(value);
        }

        NodeList invalidityDateList = dataElement.getElementsByTagName("InvalidityDate");
        if (invalidityDateList.getLength() > 0) {
            String value = invalidityDateList.item(0).getTextContent();
            request.setInvalidityDate(new Date(Long.parseLong(value)));
        }

        NodeList commentsList = dataElement.getElementsByTagName("Comments");
        if (commentsList.getLength() > 0) {
            String value = commentsList.item(0).getTextContent();
            request.setComments(value);
        }

        NodeList encodedList = dataElement.getElementsByTagName("Encoded");
        if (encodedList.getLength() > 0) {
            String value = encodedList.item(0).getTextContent();
            request.setEncoded(value);
        }

        NodeList nonceList = dataElement.getElementsByTagName("Nonce");
        if (nonceList.getLength() > 0) {
            String value = nonceList.item(0).getTextContent();
            request.setNonce(Long.parseLong(value));
        }

        return request;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element requestElement = toDOM(document);
        document.appendChild(requestElement);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);
        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);

        return sw.toString();
    }

    public static CertRevokeRequest fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element requestElement = document.getDocumentElement();
        return fromDOM(requestElement);
    }

}
