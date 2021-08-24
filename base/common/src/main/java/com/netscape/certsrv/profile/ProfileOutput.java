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
import com.netscape.certsrv.util.JSONSerializer;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfileOutput implements JSONSerializer {

    @XmlAttribute
    private String  id;

    @XmlElement
    private String name;

    @XmlElement
    private String text;

    @JsonProperty
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @XmlElement
    private String classId;

    @XmlElement(name = "attributes")
    private List<ProfileAttribute> attrs = new ArrayList<>();


    public ProfileOutput() {
        // required for jaxb
    }

    public ProfileOutput(String id, String name, String classId) {
        this.id = id;
        this.name = name;
        this.classId = classId;
    }

    @JsonProperty
    public String getClassId() {
        return classId;
    }

    public void setClassId(String classId) {
        this.classId = classId;
    }

    @JsonProperty("attributes")
    public List<ProfileAttribute> getAttrs() {
        return attrs;
    }

    public void setAttrs(List<ProfileAttribute> attrs) {
        this.attrs = attrs;
    }

    @JsonProperty
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

    public void addAttribute(ProfileAttribute attr) {
        attrs.add(attr);
    }

    public void removeAttribute(ProfileAttribute attr) {
        attrs.remove(attr);
    }

    public void clearAttributes() {
        attrs.clear();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attrs == null) ? 0 : attrs.hashCode());
        result = prime * result + ((classId == null) ? 0 : classId.hashCode());
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
        ProfileOutput other = (ProfileOutput) obj;
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

    public Element toDOM(Document document, String poElementName) {
       Element poElement = document.createElement(poElementName);
       toDOM(document, poElement);
       return poElement;
    }

    public void toDOM(Document document, Element poElement) {
        poElement.setAttribute("id", id);

        if (name != null) {
            Element nameElement = document.createElement("name");
            nameElement.appendChild(document.createTextNode(name));
            poElement.appendChild(nameElement);
        }
        if (text != null) {
            Element textElement = document.createElement("text");
            textElement.appendChild(document.createTextNode(text));
            poElement.appendChild(textElement);
        }
        if (classId != null) {
            Element classIdElement = document.createElement("classId");
            classIdElement.appendChild(document.createTextNode(classId));
            poElement.appendChild(classIdElement);
        }
        if (!attrs.isEmpty()) {
            for (ProfileAttribute attr : attrs) {
                Element attrElement = document.createElement("attributes");
                if (attr.getName() != null) {
                    attrElement.setAttribute("name", attr.getName());
                }
                if (attr.getValue() != null) {
                    Element valueElement = document.createElement("Value");
                    valueElement.appendChild(document.createTextNode(attr.getValue()));
                    attrElement.appendChild(valueElement);
                    }
                poElement.appendChild(attrElement);
            }
        }
    }

    public static ProfileOutput fromDOM(Element profileOutputElement) {

        ProfileOutput profileOutput = new ProfileOutput();
        profileOutput.setId(profileOutputElement.getAttribute("id"));

        NodeList nameList = profileOutputElement.getElementsByTagName("name");
        if (nameList.getLength() > 0) {
            profileOutput.setName(nameList.item(0).getTextContent());
        }
        NodeList textList = profileOutputElement.getElementsByTagName("text");
        if (textList.getLength() > 0) {
            profileOutput.setText(textList.item(0).getTextContent());
        }
        NodeList classIdList = profileOutputElement.getElementsByTagName("classId");
        if (classIdList.getLength() > 0) {
            profileOutput.setClassId(classIdList.item(0).getTextContent());
        }
        NodeList paList = profileOutputElement.getElementsByTagName("attributes");
        int paCount = paList.getLength();
        for (int i = 0; i < paCount; i++) {
           Element paElement = (Element) paList.item(i);
           ProfileAttribute pa = ProfileAttribute.fromDOM(paElement);
           profileOutput.addAttribute(pa);
        }
        return profileOutput;
    }

    public String toXML() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element pdElement = toDOM(document, "profileOutput");
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

    public static ProfileOutput fromXML(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element profileParameterElement = document.getDocumentElement();
        return fromDOM(profileParameterElement);
    }

}
