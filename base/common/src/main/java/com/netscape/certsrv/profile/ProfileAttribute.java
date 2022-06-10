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
package com.netscape.certsrv.profile;

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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfileAttribute implements JSONSerializer {

    private String name;
    private String value;
    private Descriptor descriptor;

    public ProfileAttribute() {
    }

    public ProfileAttribute(String name, String value, Descriptor descriptor) {
        this.name = name;
        this.value = value;
        this.descriptor = descriptor;
    }

    @JsonProperty
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("Value")
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @JsonProperty("Descriptor")
    public Descriptor getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(Descriptor descriptor) {
        this.descriptor = descriptor;
    }

    @Override
    public String toString() {
        return "PolicyAttribute [name=" + name + ", value=" + value + ", descriptor=" + descriptor + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((descriptor == null) ? 0 : descriptor.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
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
        ProfileAttribute other = (ProfileAttribute) obj;
        if (descriptor == null) {
            if (other.descriptor != null)
                return false;
        } else if (!descriptor.equals(other.descriptor))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }

    public void toDOM(Document document, Element profileAttributeElement) {

        if (name != null) {
            profileAttributeElement.setAttribute("name", name);
        }
        if (value != null) {
            Element valueElement = document.createElement("Value");
            valueElement.appendChild(document.createTextNode(value));
            profileAttributeElement.appendChild(valueElement);
        }
        if (descriptor != null) {
            Element descriptorElement = descriptor.toDOM(document);
            profileAttributeElement.appendChild(descriptorElement);
        }
    }

    public Element toDOM(Document document) {
        Element attribute = document.createElement("Attribute");
        toDOM(document, attribute);
        return attribute;
    }

    public static ProfileAttribute fromDOM(Element profileAttributeElement) {

        ProfileAttribute profileAttribute = new ProfileAttribute();

        String id = profileAttributeElement.getAttribute("name");
        profileAttribute.setName(id);

        NodeList valueList = profileAttributeElement.getElementsByTagName("Value");
        if (valueList.getLength() > 0) {
            String value = valueList.item(0).getTextContent();
            profileAttribute.setValue(value);
        }

        NodeList descriptorList = profileAttributeElement.getElementsByTagName("Descriptor");
        if (descriptorList.getLength() > 0) {
            Element descriptorElement = (Element) descriptorList.item(0);
            Descriptor descriptor = Descriptor.fromDOM(descriptorElement);
            profileAttribute.setDescriptor(descriptor);
        }

        return profileAttribute;
    }

    public String toXML() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element accountElement = toDOM(document);
        document.appendChild(accountElement);

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

    public static ProfileAttribute fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element accountElement = document.getDocumentElement();
        return fromDOM(accountElement);
    }

}
