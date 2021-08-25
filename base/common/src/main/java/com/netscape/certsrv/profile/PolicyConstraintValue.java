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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
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
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.util.JSONSerializer;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class PolicyConstraintValue implements JSONSerializer {
    @XmlAttribute(name="id")
    private String name;

    @XmlElement
    private Descriptor descriptor;

    @XmlElement
    private String value;

    public PolicyConstraintValue() {
        // required for jax-b
    }

    public PolicyConstraintValue(String name, Descriptor descriptor, String value) {
        this.name = name;
        this.descriptor = descriptor;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Descriptor getDescriptor() {
        return descriptor;
    }

    public void setDescriptor(Descriptor descriptor) {
        this.descriptor = descriptor;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
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
        PolicyConstraintValue other = (PolicyConstraintValue) obj;
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

    public Element toDOM(Document document) {

        Element pcvElement = document.createElement("policyConstraintValue");
        pcvElement.setAttribute("id", name);

        if (descriptor != null) {
            Element descriptorElement = document.createElement("descriptor");
            descriptor.toDOM(document, descriptorElement);
            pcvElement.appendChild(descriptorElement);
        }

        if (value != null) {
            Element valueElement = document.createElement("value");
            valueElement.appendChild(document.createTextNode(value.toString()));
            pcvElement.appendChild(valueElement);
        }

        return pcvElement;
    }

    public static PolicyConstraintValue fromDOM(Element pcvElement) {

        PolicyConstraintValue pcv = new PolicyConstraintValue();

        String id = pcvElement.getAttribute("id");
        pcv.setName(id);

        NodeList valueList = pcvElement.getElementsByTagName("value");
        if (valueList.getLength() > 0) {
            String value = valueList.item(0).getTextContent();
            pcv.setValue(value);
        }

        NodeList descriptorList = pcvElement.getElementsByTagName("descriptor");
        if (descriptorList.getLength() > 0) {
            Element descriptorElement = (Element) descriptorList.item(0);
            Descriptor descriptor = Descriptor.fromDOM(descriptorElement);
            pcv.setDescriptor(descriptor);
        }

        return pcv;
    }

    public String toXML() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element pcvElement = toDOM(document);
        document.appendChild(pcvElement);

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

    public static PolicyConstraintValue fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element pcvElement = document.getDocumentElement();
        return fromDOM(pcvElement);
    }

}
