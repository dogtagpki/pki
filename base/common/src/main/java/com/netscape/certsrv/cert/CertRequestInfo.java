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

package com.netscape.certsrv.cert;

import java.io.StringReader;
import java.io.StringWriter;

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
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.CMSRequestInfo;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRequestInfo extends CMSRequestInfo {

    public static final String REQ_COMPLETE = "complete";
    public static final String RES_SUCCESS = "success";
    public static final String RES_ERROR = "error";

    protected CertId certId;
    protected String certURL;
    protected String certRequestType;
    protected String operationResult;
    protected String errorMessage;

    public CertRequestInfo() {
        // required to be here for JAXB (defaults)
    }

    /**
     * @param certRequestType to set
     */

    public void setCertRequestType(String certRequestType) {
        this.certRequestType = certRequestType;
    }

    /**
     * @return the certRequestType
     */

    public String getCertRequestType() {
        return certRequestType;
    }

    /**
     * set the certURL
     */
    public void setCertURL(String certURL) {
        this.certURL = certURL;
    }

    /**
     * @return the certURL
     */
    public String getCertURL() {
        return certURL;
    }

    /**
     * @return the certId
     */
    public CertId getCertId() {
        return certId;
    }

    public void setCertId(CertId certId) {
        this.certId = certId;
    }

    public String getOperationResult() {
        return operationResult;
    }

    public void setOperationResult(String operationResult) {
        this.operationResult = operationResult;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((certId == null) ? 0 : certId.hashCode());
        result = prime * result + ((certRequestType == null) ? 0 : certRequestType.hashCode());
        result = prime * result + ((certURL == null) ? 0 : certURL.hashCode());
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
        CertRequestInfo other = (CertRequestInfo) obj;
        if (certId == null) {
            if (other.certId != null)
                return false;
        } else if (!certId.equals(other.certId))
            return false;
        if (certRequestType == null) {
            if (other.certRequestType != null)
                return false;
        } else if (!certRequestType.equals(other.certRequestType))
            return false;
        if (certURL == null) {
            if (other.certURL != null)
                return false;
        } else if (!certURL.equals(other.certURL))
            return false;
        return true;
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Element toDOM(Document document) {

        Element infoElement = document.createElement("CertDataInfo");

        toDOM(document, infoElement);

        if (certId != null) {
            infoElement.setAttribute("id", certId.toHexString());
        }

        if (certURL != null) {
            Element subjectDNElement = document.createElement("certURL");
            subjectDNElement.appendChild(document.createTextNode(certURL));
            infoElement.appendChild(subjectDNElement);
        }

        if (certRequestType != null) {
            Element issuerDNElement = document.createElement("certRequestType");
            issuerDNElement.appendChild(document.createTextNode(certRequestType));
            infoElement.appendChild(issuerDNElement);
        }

        if (operationResult != null) {
            Element statusElement = document.createElement("operationResult");
            statusElement.appendChild(document.createTextNode(operationResult));
            infoElement.appendChild(statusElement);
        }

        if (errorMessage != null) {
            Element typeElement = document.createElement("errorMessage");
            typeElement.appendChild(document.createTextNode(errorMessage));
            infoElement.appendChild(typeElement);
        }

        return infoElement;
    }

    public static CertRequestInfo fromDOM(Element infoElement) {

        CertRequestInfo info = new CertRequestInfo();

        CMSRequestInfo.fromDOM(infoElement, info);

        String id = infoElement.getAttribute("id");
        info.setCertId(StringUtils.isEmpty(id) ? null : new CertId(id));

        NodeList certURLList = infoElement.getElementsByTagName("certURL");
        if (certURLList.getLength() > 0) {
            String value = certURLList.item(0).getTextContent();
            info.setCertURL(value);
        }

        NodeList certRequestTypeList = infoElement.getElementsByTagName("certRequestType");
        if (certRequestTypeList.getLength() > 0) {
            String value = certRequestTypeList.item(0).getTextContent();
            info.setCertRequestType(value);
        }

        NodeList operationResultList = infoElement.getElementsByTagName("operationResult");
        if (operationResultList.getLength() > 0) {
            String value = operationResultList.item(0).getTextContent();
            info.setOperationResult(value);
        }

        NodeList typeList = infoElement.getElementsByTagName("errorMessage");
        if (typeList.getLength() > 0) {
            String value = typeList.item(0).getTextContent();
            info.setErrorMessage(value);
        }

        return info;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element element = toDOM(document);
        document.appendChild(element);

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

    public static CertRequestInfo fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
