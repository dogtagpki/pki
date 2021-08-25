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
public class ProfilePolicy implements JSONSerializer {
    @XmlAttribute
    private String id = null;

    @XmlElement
    private PolicyDefault def = null;

    @XmlElement
    private PolicyConstraint constraint = null;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public PolicyDefault getDef() {
        return def;
    }

    public void setDef(PolicyDefault def) {
        this.def = def;
    }

    public PolicyConstraint getConstraint() {
        return constraint;
    }

    public void setConstraint(PolicyConstraint constraint) {
        this.constraint = constraint;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((constraint == null) ? 0 : constraint.hashCode());
        result = prime * result + ((def == null) ? 0 : def.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
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
        ProfilePolicy other = (ProfilePolicy) obj;
        if (constraint == null) {
            if (other.constraint != null)
                return false;
        } else if (!constraint.equals(other.constraint))
            return false;
        if (def == null) {
            if (other.def != null)
                return false;
        } else if (!def.equals(other.def))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        return true;
    }
    public Element toDOM(Document document) {

        Element ppElement = document.createElement("profilePolicy");
        ppElement.setAttribute("id", id);

        if (def != null) {
            Element defElement = document.createElement("def");
            defElement.setAttribute("id", def.getName());
            defElement.setAttribute("classId", def.getClassId());
            ppElement.appendChild(defElement);

            if (def.getText() != null) {
                Element descriptionElement = document.createElement("description");
                descriptionElement.appendChild(document.createTextNode(def.getText()));
                defElement.appendChild(descriptionElement);
            }

            if (!def.getAttributes().isEmpty()) {
                for (ProfileAttribute attribute : def.getAttributes()) {
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
                    defElement.appendChild(attributeElement);
                }
            }
            if (!def.getParams().isEmpty()) {
                for (ProfileParameter param : def.getParams()) {
                    Element parameterElement = document.createElement("params");
                    if (param.getName() != null) {
                        parameterElement.setAttribute("name", param.getName());
                    }
                    if (param.getValue() != null) {
                        Element valueElement = document.createElement("value");
                        valueElement.appendChild(document.createTextNode(param.getValue()));
                        parameterElement.appendChild(valueElement);
                        }
                    defElement.appendChild(parameterElement);
                }
            }
        }
        if (constraint != null) {
            Element pcElement = document.createElement("constraint");
            pcElement.setAttribute("id", constraint.getName());

            if (constraint.getText() != null) {
                Element descriptionElement = document.createElement("description");
                descriptionElement.appendChild(document.createTextNode(constraint.getText()));
                pcElement.appendChild(descriptionElement);
            }
            if (constraint.getClassId() != null) {
                Element classIdElement = document.createElement("classId");
                classIdElement.appendChild(document.createTextNode(constraint.getClassId()));
                pcElement.appendChild(classIdElement);
            }
            if (constraint.getConstraints() != null) {
                for (PolicyConstraintValue pcv : constraint.getConstraints()) {
                    Element constraintElement = document.createElement("constraint");
                    constraintElement.setAttribute("id", pcv.getName());
                    Descriptor descriptor = pcv.getDescriptor();
                    if (descriptor != null) {
                        Element descriptorElement = document.createElement("descriptor");
                        descriptor.toDOM(document, descriptorElement);
                        constraintElement.appendChild(descriptorElement);
                    }
                    if (pcv.getValue() != null) {
                        Element valueElement = document.createElement("value");
                        valueElement.appendChild(document.createTextNode(pcv.getValue()));
                        constraintElement.appendChild(valueElement);
                    }
                    pcElement.appendChild(constraintElement);
                }
            }
            ppElement.appendChild(pcElement);
        }
        return ppElement;
    }

    public static ProfilePolicy fromDOM(Element profilePolicyElement) {

        ProfilePolicy profilePolicy = new ProfilePolicy();
        profilePolicy.setId(profilePolicyElement.getAttribute("id"));
        NodeList ppList = profilePolicyElement.getElementsByTagName("def");
        if (ppList.getLength() > 0) {
            Element ppElement = (Element) ppList.item(0);
            PolicyDefault pd = PolicyDefault.fromDOM(ppElement);
            profilePolicy.setDef(pd);
        }
        NodeList constraintsList = profilePolicyElement.getElementsByTagName("constraint");
        if (constraintsList.getLength() > 0) {
            PolicyConstraint pc = new PolicyConstraint();
            Element constraintsElement = (Element) constraintsList.item(0);
            String id = constraintsElement.getAttribute("id");
            pc.setName(id);
            NodeList descriptionList = constraintsElement.getElementsByTagName("description");
            if (descriptionList.getLength() > 0) {
                String text = descriptionList.item(0).getTextContent();
                pc.setText(text);
            }
            NodeList classIdList = constraintsElement.getElementsByTagName("classId");
            if (classIdList.getLength() > 0) {
                String classId = classIdList.item(0).getTextContent();
                pc.setClassId(classId);
            }

            NodeList constraintList = constraintsElement.getElementsByTagName("constraint");
            int constraintCount = constraintList.getLength();
            for (int i = 0; i < constraintCount; i++) {
               Element constraintElement = (Element) constraintList.item(i);
               PolicyConstraintValue pcv = new PolicyConstraintValue();
               pcv.setName(constraintElement.getAttribute("id"));

               NodeList nameList = constraintElement.getElementsByTagName("name");
               if (nameList.getLength() > 0) {
                   String name = nameList.item(0).getTextContent();
                   pcv.setName(name);
               }

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
               }

               pc.addConstraint(pcv);
            }
            profilePolicy.setConstraint(pc);
        }
        return profilePolicy;
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

    public static ProfilePolicy fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element profileParameterElement = document.getDocumentElement();
        return fromDOM(profileParameterElement);
    }

}
