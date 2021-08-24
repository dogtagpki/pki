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
import java.util.Locale;

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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.util.JSONSerializer;

@XmlRootElement(name="Attribute")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfileAttribute implements JSONSerializer {

    @XmlAttribute
    private String name;

    @XmlElement(name="Value")
    private String value;

    @XmlElement(name="Descriptor")
    private Descriptor descriptor;

    public ProfileAttribute() {
        // required for jax-b
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

    public Element toDOM(Document document) {

        Element profileAttributeElement = document.createElement("Attribute");

        if (name != null) {
            profileAttributeElement.setAttribute("name", name);
        }
        if (value != null) {
            Element valueElement = document.createElement("Value");
            valueElement.appendChild(document.createTextNode(value));
            profileAttributeElement.appendChild(valueElement);
        }
        if (descriptor != null) {
            Element descriptorElement = document.createElement("Descriptor");

            if (descriptor.getSyntax() != null) {
                Element syntaxElement = document.createElement("mSyntax");
                syntaxElement.appendChild(document.createTextNode(descriptor.getSyntax()));
                descriptorElement.appendChild(syntaxElement);
            }

            if (descriptor.getConstraint() != null) {
                Element constraintElement = document.createElement("mConstraint");
                constraintElement.appendChild(document.createTextNode(descriptor.getConstraint()));
                descriptorElement.appendChild(constraintElement);
            }

            if (descriptor.getDescription(Locale.getDefault()) != null) {
                Element descriptionElement = document.createElement("mDescription");
                descriptionElement.appendChild(document.createTextNode(descriptor.getDescription(Locale.getDefault())));
                descriptorElement.appendChild(descriptionElement);
            }

            if (descriptor.getDefaultValue() != null) {
                Element defaultValueElement = document.createElement("mDef");
                defaultValueElement.appendChild(document.createTextNode(descriptor.getDefaultValue()));
                descriptorElement.appendChild(defaultValueElement);
            }
            profileAttributeElement.appendChild(descriptorElement);
        }
        return profileAttributeElement;
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
            String syntax = null;
            String constraint = null;
            String description = null;
            String def = null;
            NodeList syntaxList = profileAttributeElement.getElementsByTagName("mSyntax");
            NodeList constraintList = profileAttributeElement.getElementsByTagName("mConstraint");
            NodeList descriptionList = profileAttributeElement.getElementsByTagName("mDescription");
            NodeList defList = profileAttributeElement.getElementsByTagName("mDef");
            if (syntaxList.getLength() > 0) {
                syntax = syntaxList.item(0).getTextContent();
            }
            if (constraintList.getLength() > 0) {
                constraint = constraintList.item(0).getTextContent();
            }
            if (descriptionList.getLength() > 0) {
                description = descriptionList.item(0).getTextContent();
            }
            if (defList.getLength() > 0) {
                def = defList.item(0).getTextContent();
            }
            Descriptor descriptor = new Descriptor(syntax, constraint, def, description);
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
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element accountElement = document.getDocumentElement();
        return fromDOM(accountElement);
    }

}
