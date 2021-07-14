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
import java.util.Objects;

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
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRetrievalRequest implements JSONSerializer {

    protected CertId certId;
    public RequestId requestId;

    public CertRetrievalRequest() {
    }

    public CertRetrievalRequest(CertId certId) {
        this.certId = certId;
    }

    /**
     * @return the CertId
     */
    public CertId getCertId() {
        return certId;
    }

    protected void setCertId(CertId certId) {
        this.certId = certId;
    }

    protected void setRequestId(RequestId requestId) {
        this.requestId = requestId;
    }

    public Element toDOM(Document document) {

        Element requestElement = document.createElement("CertRetrievalRequest");

        if (certId != null) {
            Element issuerDNElement = document.createElement("certId");
            issuerDNElement.appendChild(document.createTextNode(certId.toHexString()));
            requestElement.appendChild(issuerDNElement);
        }

        if (requestId != null) {
            Element issuerDNElement = document.createElement("requestId");
            issuerDNElement.appendChild(document.createTextNode(requestId.toString()));
            requestElement.appendChild(issuerDNElement);
        }

        return requestElement;
    }

    public static CertRetrievalRequest fromDOM(Element requestElement) {

        CertRetrievalRequest request = new CertRetrievalRequest();

        NodeList certIdList = requestElement.getElementsByTagName("certId");
        if (certIdList.getLength() > 0) {
            String value = certIdList.item(0).getTextContent();
            request.setCertId(new CertId(value));
        }

        NodeList requestIdList = requestElement.getElementsByTagName("requestId");
        if (requestIdList.getLength() > 0) {
            String value = requestIdList.item(0).getTextContent();
            request.setRequestId(new RequestId(value));
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
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);
        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);

        return sw.toString();
    }

    public static CertRetrievalRequest fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element requestElement = document.getDocumentElement();
        return fromDOM(requestElement);

    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(certId, requestId);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertRetrievalRequest other = (CertRetrievalRequest) obj;
        return Objects.equals(certId, other.certId) && Objects.equals(requestId, other.requestId);
    }

}
