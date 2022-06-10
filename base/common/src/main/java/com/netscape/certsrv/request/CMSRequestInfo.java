//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.request;

import java.io.StringReader;
import java.io.StringWriter;

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

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CMSRequestInfo implements JSONSerializer {

    protected RequestId requestID;
    protected String requestType;
    protected RequestStatus requestStatus;
    protected String requestURL;
    protected String realm;

    public RequestId getRequestID() {
        return requestID;
    }

    public void setRequestID(RequestId requestID) {
        this.requestID = requestID;
    }

    /**
     * @return the requestType
     */
    public String getRequestType() {
        return requestType;
    }

    /**
     * @param requestType the requestType to set
     */
    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    /**
     * @return the requestStatus
     */
    public RequestStatus getRequestStatus() {
        return requestStatus;
    }

    /**
     * @param requestStatus the requestStatus to set
     */
    public void setRequestStatus(RequestStatus requestStatus) {
        this.requestStatus = requestStatus;
    }

    /**
     * @return the requestURL
     */
    public String getRequestURL() {
        return requestURL;
    }

    /**
     * @return the request ID in the requestURL
     * @deprecated Use getRequestID() instead.
     */
    @Deprecated(since = "11.2.0", forRemoval = true)
    public RequestId getRequestId() {

        if (requestURL == null) {
            return null;
        }

        String id = requestURL.substring(requestURL.lastIndexOf("/") + 1);
        return new RequestId(id);
    }

    /**
     * @param requestURL the requestURL to set
     */
    public void setRequestURL(String requestURL) {
        this.requestURL = requestURL;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((realm == null) ? 0 : realm.hashCode());
        result = prime * result + ((requestID == null) ? 0 : requestID.hashCode());
        result = prime * result + ((requestStatus == null) ? 0 : requestStatus.hashCode());
        result = prime * result + ((requestType == null) ? 0 : requestType.hashCode());
        result = prime * result + ((requestURL == null) ? 0 : requestURL.hashCode());
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
        CMSRequestInfo other = (CMSRequestInfo) obj;
        if (realm == null) {
            if (other.realm != null)
                return false;
        } else if (!realm.equals(other.realm))
            return false;
        if (requestID == null) {
            if (other.requestID != null)
                return false;
        } else if (!requestID.equals(other.requestID))
            return false;
        if (requestStatus == null) {
            if (other.requestStatus != null)
                return false;
        } else if (!requestStatus.equals(other.requestStatus))
            return false;
        if (requestType == null) {
            if (other.requestType != null)
                return false;
        } else if (!requestType.equals(other.requestType))
            return false;
        if (requestURL == null) {
            if (other.requestURL != null)
                return false;
        } else if (!requestURL.equals(other.requestURL))
            return false;
        return true;
    }

    public void toDOM(Document document, Element infoElement) {

        if (requestID != null) {
            Element requestTypeElement = document.createElement("requestID");
            requestTypeElement.appendChild(document.createTextNode(requestID.toHexString()));
            infoElement.appendChild(requestTypeElement);
        }

        if (requestType != null) {
            Element requestTypeElement = document.createElement("requestType");
            requestTypeElement.appendChild(document.createTextNode(requestType));
            infoElement.appendChild(requestTypeElement);
        }

        if (requestStatus != null) {
            Element requestStatusElement = document.createElement("requestStatus");
            requestStatusElement.appendChild(document.createTextNode(requestStatus.toString()));
            infoElement.appendChild(requestStatusElement);
        }

        if (requestURL != null) {
            Element requestURLElement = document.createElement("requestURL");
            requestURLElement.appendChild(document.createTextNode(requestURL));
            infoElement.appendChild(requestURLElement);
        }

        if (realm != null) {
            Element realmElement = document.createElement("realm");
            realmElement.appendChild(document.createTextNode(realm));
            infoElement.appendChild(realmElement);
        }
    }

    public Element toDOM(Document document) {
        Element infoElement = document.createElement("CMSRequestInfo");
        toDOM(document, infoElement);
        return infoElement;
    }

    public static void fromDOM(Element infoElement, CMSRequestInfo info) {

        NodeList requestIDList = infoElement.getElementsByTagName("requestID");
        if (requestIDList.getLength() > 0) {
            String value = requestIDList.item(0).getTextContent();
            info.setRequestID(new RequestId(value));
        }

        NodeList requestTypeList = infoElement.getElementsByTagName("requestType");
        if (requestTypeList.getLength() > 0) {
            String value = requestTypeList.item(0).getTextContent();
            info.setRequestType(value);
        }

        NodeList requestStatusList = infoElement.getElementsByTagName("requestStatus");
        if (requestStatusList.getLength() > 0) {
            String value = requestStatusList.item(0).getTextContent();
            info.setRequestStatus(RequestStatus.valueOf(value));
        }

        NodeList requestURLList = infoElement.getElementsByTagName("requestURL");
        if (requestURLList.getLength() > 0) {
            String value = requestURLList.item(0).getTextContent();
            info.setRequestURL(value);
        }

        NodeList realmList = infoElement.getElementsByTagName("realm");
        if (realmList.getLength() > 0) {
            String value = realmList.item(0).getTextContent();
            info.setRealm(value);
        }
    }

    public static CMSRequestInfo fromDOM(Element infoElement) {
        CMSRequestInfo info = new CMSRequestInfo();
        fromDOM(infoElement, info);
        return info;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element element = toDOM(document);
        document.appendChild(element);

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

    public static CMSRequestInfo fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
