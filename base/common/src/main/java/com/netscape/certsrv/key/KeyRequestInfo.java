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

package com.netscape.certsrv.key;

import java.io.StringReader;
import java.io.StringWriter;

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
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.CMSRequestInfo;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KeyRequestInfo extends CMSRequestInfo {

    protected String keyURL;

    public KeyRequestInfo() {
        // required to be here for JAXB (defaults)
    }

    /**
     * @return the keyURL
     */
    public String getKeyURL() {
        return keyURL;
    }

    /**
     * @return the key ID in the keyURL
     */
    public KeyId getKeyId() {
        if (keyURL == null) return null;
        String id = keyURL.substring(keyURL.lastIndexOf("/") + 1);
        return new KeyId(id);
    }

    /**
     * @param keyURL the keyURL to set
     */
    public void setKeyURL(String keyURL) {
        this.keyURL = keyURL;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((keyURL == null) ? 0 : keyURL.hashCode());
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
        KeyRequestInfo other = (KeyRequestInfo) obj;
        if (keyURL == null) {
            if (other.keyURL != null)
                return false;
        } else if (!keyURL.equals(other.keyURL))
            return false;
        return true;
    }

    @Override
    public Element toDOM(Document document) {

        Element infoElement = document.createElement("CertDataInfo");

        toDOM(document, infoElement);

        if (keyURL != null) {
            Element subjectDNElement = document.createElement("keyURL");
            subjectDNElement.appendChild(document.createTextNode(keyURL));
            infoElement.appendChild(subjectDNElement);
        }

        return infoElement;
    }

    public static KeyRequestInfo fromDOM(Element infoElement) {

        KeyRequestInfo info = new KeyRequestInfo();

        CMSRequestInfo.fromDOM(infoElement, info);

        NodeList keyURLList = infoElement.getElementsByTagName("keyURL");
        if (keyURLList.getLength() > 0) {
            String value = keyURLList.item(0).getTextContent();
            info.setKeyURL(value);
        }

        return info;
    }

    @Override
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

    public static KeyRequestInfo fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
