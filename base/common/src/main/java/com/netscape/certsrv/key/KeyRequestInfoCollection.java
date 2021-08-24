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
import java.util.Collection;

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
import com.netscape.certsrv.base.DataCollection;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KeyRequestInfoCollection extends DataCollection<KeyRequestInfo> implements JSONSerializer {

    @Override
    public Collection<KeyRequestInfo> getEntries() {
        return super.getEntries();
    }

    public String getNext() {
        for (Link link : getLinks()) {
            if ("next".equals(link.getRelationship())) {
                return link.getHref().toString();
            }
        }
        return null;
    }

    public String getPrevious() {
        for (Link link : getLinks()) {
            if ("previous".equals(link.getRelationship())) {
                return link.getHref().toString();
            }
        }
        return null;
    }

    public Element toDOM(Document document) {

        Element infosElement = document.createElement("KeyRequestInfoCollection");

        Element totalElement = document.createElement("total");
        totalElement.appendChild(document.createTextNode(Integer.toString(total)));
        infosElement.appendChild(totalElement);

        for (KeyRequestInfo keyRequestInfo : getEntries()) {
            Element infoElement = keyRequestInfo.toDOM(document);
            infosElement.appendChild(infoElement);
        }

        for (Link link : getLinks()) {
            Element infoElement = link.toDOM(document);
            infosElement.appendChild(infoElement);
        }

        return infosElement;
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

    public static KeyRequestInfoCollection fromDOM(Element infosElement) {

        KeyRequestInfoCollection infos = new KeyRequestInfoCollection();

        NodeList totalList = infosElement.getElementsByTagName("total");
        if (totalList.getLength() > 0) {
            String value = totalList.item(0).getTextContent();
            infos.setTotal(Integer.parseInt(value));
        }

        NodeList infoList = infosElement.getElementsByTagName("KeyRequestInfo");
        int infoCount = infoList.getLength();
        for (int i=0; i<infoCount; i++) {
           Element infoElement = (Element) infoList.item(i);
           KeyRequestInfo info = KeyRequestInfo.fromDOM(infoElement);
           infos.addEntry(info);
        }

        NodeList linkList = infosElement.getElementsByTagName("Link");
        int linkCount = linkList.getLength();
        for (int i=0; i<linkCount; i++) {
           Element linkElement = (Element) linkList.item(i);
           Link link = Link.fromDOM(linkElement);
           infos.addLink(link);
        }

        return infos;
    }

    public static KeyRequestInfoCollection fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
