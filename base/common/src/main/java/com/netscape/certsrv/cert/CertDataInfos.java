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
package com.netscape.certsrv.cert;

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
import com.netscape.certsrv.base.DataCollection;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertDataInfos extends DataCollection<CertDataInfo> implements JSONSerializer {

    public Element toDOM(Document document) {

        Element infosElement = document.createElement("CertDataInfos");
        document.appendChild(infosElement);

        Element totalElement = document.createElement("total");
        totalElement.appendChild(document.createTextNode(Integer.toString(total)));
        infosElement.appendChild(totalElement);

        for (CertDataInfo certDataInfo : getEntries()) {
            Element infoElement = certDataInfo.toDOM(document);
            infosElement.appendChild(infoElement);
        }

        return infosElement;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        toDOM(document);

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

    public static CertDataInfos fromDOM(Element infosElement) {

        CertDataInfos infos = new CertDataInfos();

        NodeList totalList = infosElement.getElementsByTagName("total");
        if (totalList.getLength() > 0) {
            String value = totalList.item(0).getTextContent();
            infos.setTotal(Integer.parseInt(value));
        }

        NodeList infoList = infosElement.getElementsByTagName("CertDataInfo");
        int infoCount = infoList.getLength();
        for (int i=0; i<infoCount; i++) {
           Element infoElement = (Element) infoList.item(i);
           CertDataInfo info = CertDataInfo.fromDOM(infoElement);
           infos.addEntry(info);
        }

        return infos;
    }

    public static CertDataInfos fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element infosElement = document.getDocumentElement();
        return fromDOM(infosElement);
    }
}
