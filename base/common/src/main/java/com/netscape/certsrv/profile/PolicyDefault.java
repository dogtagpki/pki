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
import java.util.ArrayList;
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
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.util.JSONSerializer;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class PolicyDefault implements JSONSerializer {
    @XmlAttribute(name="id")
    private String name;

    @XmlAttribute
    private String classId;

    @XmlElement(name="description")
    private String text;

    @XmlElement(name="policyAttribute")
    private List<ProfileAttribute> attributes = new ArrayList<>();

    @XmlElement(name = "params")
    private List<ProfileParameter> params = new ArrayList<>();

    public PolicyDefault() {
        // required for jaxb
    }

    public void addAttribute(ProfileAttribute attr) {
        attributes.add(attr);
    }

    public void addParameter(ProfileParameter param) {
        params.add(param);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getClassId() {
        return classId;
    }

    public void setClassId(String classId) {
        this.classId = classId;
    }

    public List<ProfileAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<ProfileAttribute> attributes) {
        this.attributes = attributes;
    }

    public List<ProfileParameter> getParams() {
        return params;
    }

    public void setParams(List<ProfileParameter> params) {
        this.params = params;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
        result = prime * result + ((classId == null) ? 0 : classId.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((params == null) ? 0 : params.hashCode());
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
        PolicyDefault other = (PolicyDefault) obj;
        if (attributes == null) {
            if (other.attributes != null)
                return false;
        } else if (!attributes.equals(other.attributes))
            return false;
        if (classId == null) {
            if (other.classId != null)
                return false;
        } else if (!classId.equals(other.classId))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (params == null) {
            if (other.params != null)
                return false;
        } else if (!params.equals(other.params))
            return false;
        if (text == null) {
            if (other.text != null)
                return false;
        } else if (!text.equals(other.text))
            return false;
        return true;
    }

    public Element toDOM(Document document) {

        Element pdElement = document.createElement("policyDefault");
        pdElement.setAttribute("id", name);
        pdElement.setAttribute("classId", classId);

        if (text != null) {
            Element descriptionElement = document.createElement("description");
            descriptionElement.appendChild(document.createTextNode(text));
            pdElement.appendChild(descriptionElement);
        }

        for (ProfileAttribute attribute : attributes) {
            Element attributeElement = document.createElement("policyAttribute");
            if (attribute.getName() != null) {
                attributeElement.setAttribute("name", attribute.getName());
            }
            if (attribute.getValue() != null) {
                Element valueElement = document.createElement("Value");
                valueElement.appendChild(document.createTextNode(attribute.getValue()));
                attributeElement.appendChild(valueElement);
            }
            Descriptor descriptor = attribute.getDescriptor();
            if (descriptor != null) {
                Element descriptorElement = descriptor.toDOM(document);
                attributeElement.appendChild(descriptorElement);
            }
            pdElement.appendChild(attributeElement);
        }
        for (ProfileParameter param : params) {
            Element parameterElement = document.createElement("params");
            if (param.getName() != null) {
                parameterElement.setAttribute("name", param.getName());
            }
            if (param.getValue() != null) {
                Element valueElement = document.createElement("value");
                valueElement.appendChild(document.createTextNode(param.getValue()));
                parameterElement.appendChild(valueElement);
                }
            pdElement.appendChild(parameterElement);
        }
        return pdElement;
    }

    public static PolicyDefault fromDOM(Element policyDefaultElement) {

        PolicyDefault policyDefault = new PolicyDefault();
        policyDefault.setName(policyDefaultElement.getAttribute("id"));
        policyDefault.setClassId(policyDefaultElement.getAttribute("classId"));

        NodeList descriptionList = policyDefaultElement.getElementsByTagName("description");
        if (descriptionList.getLength() > 0) {
             policyDefault.setText(descriptionList.item(0).getTextContent());
        }
        NodeList paList = policyDefaultElement.getElementsByTagName("policyAttribute");
        int paCount = paList.getLength();
        for (int i = 0; i < paCount; i++) {
           Element paElement = (Element) paList.item(i);
           ProfileAttribute pa = ProfileAttribute.fromDOM(paElement);
           policyDefault.addAttribute(pa);
        }
        NodeList ppList = policyDefaultElement.getElementsByTagName("params");
        int ppCount = ppList.getLength();
        for (int i = 0; i < ppCount; i++) {
           Element ppElement = (Element) ppList.item(i);
           ProfileParameter pp = ProfileParameter.fromDOM(ppElement);
           policyDefault.addParameter(pp);
        }
        return policyDefault;
    }

    public String toXML() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element pdElement = toDOM(document);
        document.appendChild(pdElement);

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

    public static PolicyDefault fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element profileParameterElement = document.getDocumentElement();
        return fromDOM(profileParameterElement);
    }

}
