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

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.CertIdAdapter;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestIdAdapter;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "CertRetrievalRequest")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRetrievalRequest implements JSONSerializer {

    @XmlElement
    @XmlJavaTypeAdapter(CertIdAdapter.class)
    protected CertId certId;

    @XmlElement
    @XmlJavaTypeAdapter(RequestIdAdapter.class)
    public RequestId requestId;

    public CertRetrievalRequest() {
        // required for JAXB (defaults)
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
        Marshaller marshaller = JAXBContext.newInstance(CertRetrievalRequest.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static CertRetrievalRequest fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(CertRetrievalRequest.class).createUnmarshaller();
        return (CertRetrievalRequest) unmarshaller.unmarshal(new StringReader(xml));
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
