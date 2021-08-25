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

import org.w3c.dom.DOMException;
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
public class PolicyConstraint implements JSONSerializer {
    @XmlAttribute(name="id")
    private String name;

    @XmlElement(name="description")
    private String text;

    @XmlElement
    private String classId;

    @XmlElement(name = "constraint")
    private List<PolicyConstraintValue> constraints = new ArrayList<>();

    public PolicyConstraint() {
        // required for jaxb
    }

    public void addConstraint(PolicyConstraintValue constraint) {
        constraints.add(constraint);
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

    public List<PolicyConstraintValue> getConstraints() {
        return constraints;
    }

    public void setConstraints(List<PolicyConstraintValue> constraints) {
        this.constraints = constraints;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((classId == null) ? 0 : classId.hashCode());
        result = prime * result + ((constraints == null) ? 0 : constraints.hashCode());
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
        PolicyConstraint other = (PolicyConstraint) obj;
        if (classId == null) {
            if (other.classId != null)
                return false;
        } else if (!classId.equals(other.classId))
            return false;
        if (constraints == null) {
            if (other.constraints != null)
                return false;
        } else if (!constraints.equals(other.constraints))
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

        Element pcvElement = document.createElement("policyConstraint");
        pcvElement.setAttribute("id", name);

        if (text != null) {
            Element descriptionElement = document.createElement("description");
            descriptionElement.appendChild(document.createTextNode(text));
            pcvElement.appendChild(descriptionElement);
        }
        if (classId != null) {
            Element classIdElement = document.createElement("classId");
            classIdElement.appendChild(document.createTextNode(classId));
            pcvElement.appendChild(classIdElement);
        }
        if (constraints != null) {
            for (PolicyConstraintValue pcv : constraints) {
                Element constraintElement = document.createElement("constraint");
                Descriptor descriptor = pcv.getDescriptor();
                if (descriptor != null) {
                    Element descriptorElement = document.createElement("descriptor");
                    descriptor.toDOM(document, descriptorElement);
                    constraintElement.appendChild(descriptorElement);
                    if (pcv.getName() != null) {
                        constraintElement.setAttribute("id", pcv.getName());
                    }
                    if (pcv.getValue() != null) {
                        Element valueElement = document.createElement("value");
                        valueElement.appendChild(document.createTextNode(pcv.getValue()));
                        constraintElement.appendChild(valueElement);
                    }
                }
                pcvElement.appendChild(constraintElement);
            }
        }
        return pcvElement;
    }

    public static PolicyConstraint fromDOM(Element pcElement) throws DOMException, Exception {

        PolicyConstraint pc = new PolicyConstraint();

        String id = pcElement.getAttribute("id");
        pc.setName(id);

        NodeList descriptionList = pcElement.getElementsByTagName("description");
        if (descriptionList.getLength() > 0) {
            String text = descriptionList.item(0).getTextContent();
            pc.setText(text);
        }

        NodeList classIdList = pcElement.getElementsByTagName("classId");
        if (classIdList.getLength() > 0) {
            String classId = classIdList.item(0).getTextContent();
            pc.setClassId(classId);
        }

        NodeList constraintList = pcElement.getElementsByTagName("constraint");
        int constraintCount = constraintList.getLength();
        for (int i = 0; i < constraintCount; i++) {
           Element constraintElement = (Element) constraintList.item(i);
           PolicyConstraintValue pcv = new PolicyConstraintValue();

           String pcvId = constraintElement.getAttribute("id");
           pcv.setName(pcvId);

           NodeList valueList = constraintElement.getElementsByTagName("value");
           if (valueList.getLength() > 0) {
               String value = valueList.item(0).getTextContent();
               pcv.setValue(value);
           }

           NodeList descriptorList = constraintElement.getElementsByTagName("descriptor");
           if (descriptorList.getLength() > 0) {
               Element descriptorElement = (Element) descriptorList.item(0);
               Descriptor descriptor = Descriptor.fromDOM(descriptorElement);
               pcv.setDescriptor(descriptor);
               pc.addConstraint(pcv);
           }
        }
        return pc;
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

        public static PolicyConstraint fromXML(String xml) throws Exception {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(xml)));

            Element accountElement = document.getDocumentElement();
            return fromDOM(accountElement);
        }

}
