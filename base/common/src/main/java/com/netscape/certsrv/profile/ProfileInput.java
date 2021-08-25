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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.profile;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

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

@XmlRootElement(name="Input")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfileInput implements JSONSerializer {

    @XmlAttribute(name="id")
    private String id;

    @XmlElement(name="ClassID")
    private String classId;

    @XmlElement(name="Name")
    private String name;

    @XmlElement(name="Text")
    private String text;

    @XmlElement(name = "Attribute")
    private List<ProfileAttribute> attrs = new ArrayList<>();

    @XmlElement(name = "ConfigAttribute")
    private List<ProfileAttribute> configAttrs = new ArrayList<>();

    public ProfileInput() {
        // required for jaxb
    }

    public ProfileInput(String id, String name, String classId) {
        this.id = id;
        this.name = name;
        this.classId = classId;
    }

    @JsonProperty("ClassID")
    public String getClassId() {
        return classId;
    }

    @JsonProperty("Name")
    public String getName() {
        return name;
    }

    @JsonProperty("Text")
    public String getText() {
        return text;
    }

    public void setClassId(String classId) {
        this.classId = classId;
    }

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setText(String text) {
        this.text = text;
    }

    @JsonProperty("Attribute")
    public Collection<ProfileAttribute> getAttributes() {
        return attrs;
    }

    public void setAttributes(Collection<ProfileAttribute> attrs) {
        this.attrs.clear();
        this.attrs.addAll(attrs);
    }

    public ProfileAttribute getAttribute(String name) {
        for (ProfileAttribute attr : attrs) {
            if (attr.getName().equals(name)) return attr;
        }
        return null;
    }

    public void addAttribute(ProfileAttribute attr) {
        attrs.add(attr);
    }

    public void removeAttribute(String name) {
        attrs.remove(name);
    }

    public void clearAttributes() {
        attrs.clear();
    }

    @JsonProperty("ConfigAttribute")
    public List<ProfileAttribute> getConfigAttrs() {
        return configAttrs;
    }

    public void setConfigAttrs(List<ProfileAttribute> configAttrs) {
        this.configAttrs = configAttrs;
    }

    public void addConfigAttribute(ProfileAttribute configAttr) {
        configAttrs.add(configAttr);
    }

    public void removeConfigAttribute(ProfileAttribute configAttr) {
        configAttrs.remove(configAttr);
    }

    public void clearConfigAttributes() {
        configAttrs.clear();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attrs == null) ? 0 : attrs.hashCode());
        result = prime * result + ((classId == null) ? 0 : classId.hashCode());
        result = prime * result + ((configAttrs == null) ? 0 : configAttrs.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((text == null) ? 0 : text.hashCode());
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
        ProfileInput other = (ProfileInput) obj;
        if (attrs == null) {
            if (other.attrs != null)
                return false;
        } else if (!attrs.equals(other.attrs))
            return false;
        if (classId == null) {
            if (other.classId != null)
                return false;
        } else if (!classId.equals(other.classId))
            return false;
        if (configAttrs == null) {
            if (other.configAttrs != null)
                return false;
        } else if (!configAttrs.equals(other.configAttrs))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (text == null) {
            if (other.text != null)
                return false;
        } else if (!text.equals(other.text))
            return false;
        return true;
    }

    public Element toDOM(Document document) {

        Element profileInputElement = document.createElement("Input");

        if (id != null) {
            profileInputElement.setAttribute("id", id);
        }

        if (name != null) {
            Element nameElement = document.createElement("Name");
            nameElement.appendChild(document.createTextNode(name));
            profileInputElement.appendChild(nameElement);
        }

        for (ProfileAttribute attribute : attrs) {
            Element attributeElement = document.createElement("Attribute");
            String name = attribute.getName();
            if (name != null) {
                attributeElement.setAttribute("name", name);
            }

            String value = attribute.getValue();
            if (value != null) {
                Element valueElement = document.createElement("Value");
                valueElement.appendChild(document.createTextNode(value));
                attributeElement.appendChild(valueElement);
            }

            Descriptor descriptor = attribute.getDescriptor();
            if (descriptor != null) {
                Element descriptorElement = descriptor.toDOM(document);
                attributeElement.appendChild(descriptorElement);
            }

            profileInputElement.appendChild(attributeElement);
        }

        for (ProfileAttribute configAttribute : configAttrs) {
            Element attributeElement = document.createElement("ConfigAttribute");
            String name = configAttribute.getName();
            if (name != null) {
                attributeElement.setAttribute("name", name);
            }

            String value = configAttribute.getValue();
            if (value != null) {
                Element valueElement = document.createElement("Value");
                valueElement.appendChild(document.createTextNode(value));
                attributeElement.appendChild(valueElement);
            }

            Descriptor descriptor = configAttribute.getDescriptor();
            if (descriptor != null) {
                Element descriptorElement = descriptor.toDOM(document);
                attributeElement.appendChild(descriptorElement);
            }

            profileInputElement.appendChild(attributeElement);
        }

        return profileInputElement;
    }

    public static ProfileInput fromDOM(Element profileInputElement) {

        ProfileInput profileInput = new ProfileInput();

        String id = profileInputElement.getAttribute("id");
        profileInput.setId(id);

        NodeList nameList = profileInputElement.getElementsByTagName("Name");
        if (nameList.getLength() > 0) {
            String value = nameList.item(0).getTextContent();
            profileInput.setName(value);
        }

        NodeList attributeList = profileInputElement.getElementsByTagName("Attribute");
        for (int i = 0; i < attributeList.getLength(); i++) {
            Element attributeElement = (Element) attributeList.item(i);
            ProfileAttribute profileAttribute = new ProfileAttribute();

            String attributeId = attributeElement.getAttribute("name");
            profileAttribute.setName(attributeId);

            NodeList valueList = attributeElement.getElementsByTagName("Value");
            if (valueList.getLength() > 0) {
                String value = valueList.item(0).getTextContent();
                profileAttribute.setValue(value);
            }

            NodeList descriptorList = attributeElement.getElementsByTagName("Descriptor");
            if (descriptorList.getLength() > 0) {
                Element descriptorElement = (Element) descriptorList.item(0);
                Descriptor descriptor = Descriptor.fromDOM(descriptorElement);
                profileAttribute.setDescriptor(descriptor);
            }
            profileInput.addAttribute(profileAttribute);
        }

        NodeList configAttributeList = profileInputElement.getElementsByTagName("ConfigAttribute");
        for (int i = 0; i < configAttributeList.getLength(); i++) {
            Element configAttributeElement = (Element) configAttributeList.item(i);
            ProfileAttribute profileAttribute = new ProfileAttribute();
            String configAttributeId = configAttributeElement.getAttribute("name");
            profileAttribute.setName(configAttributeId);

            NodeList configAttributeNameList = configAttributeElement.getElementsByTagName("Name");
            if (configAttributeNameList.getLength() > 0) {
                String name = configAttributeNameList.item(0).getTextContent();
                profileAttribute.setName(name);
            }

            NodeList valueList = configAttributeElement.getElementsByTagName("Value");
            if (valueList.getLength() > 0) {
                String value = valueList.item(0).getTextContent();
                profileAttribute.setValue(value);
            }

            NodeList descriptorList = configAttributeElement.getElementsByTagName("Descriptor");
            if (descriptorList.getLength() > 0) {
                Element descriptorElement = (Element) descriptorList.item(0);
                Descriptor descriptor = Descriptor.fromDOM(descriptorElement);
                profileAttribute.setDescriptor(descriptor);
            }
            profileInput.addConfigAttribute(profileAttribute);
         }
        return profileInput;
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

    public static ProfileInput fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element profileElement = document.getDocumentElement();
        return fromDOM(profileElement);
    }

}
