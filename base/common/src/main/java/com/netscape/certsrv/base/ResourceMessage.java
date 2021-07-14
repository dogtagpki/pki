package com.netscape.certsrv.base;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.OutputStream;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Ade Lee
 */
@JsonInclude(Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ResourceMessage implements JSONSerializer {

    protected Map<String, String> attributes = new LinkedHashMap<>();
    protected String className;

    public ResourceMessage() {
        // required for jax-b
    }

    public ResourceMessage(MultivaluedMap<String, String> form) {
        for (Map.Entry<String, List<String>> entry : form.entrySet()) {
            attributes.put(entry.getKey(), entry.getValue().get(0));
        }
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes.clear();
        this.attributes.putAll(attributes);
    }

    @JsonIgnore
    public Collection<String> getAttributeNames() {
        return attributes.keySet();
    }

    public String getAttribute(String name) {
        return attributes.get(name);
    }

    public void setAttribute(String name, String value) {
        attributes.put(name, value);
    }

    public String removeAttribute(String name) {
        return attributes.remove(name);
    }

     public static class AttributeList {
        public List<Attribute> attrs = new ArrayList<>();
    }

    public static class Attribute {

        public String name;

        public String value;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((attributes == null) ? 0 : attributes.hashCode());
        result = prime * result + ((className == null) ? 0 : className.hashCode());
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
        ResourceMessage other = (ResourceMessage) obj;
        if (attributes == null) {
            if (other.attributes != null)
                return false;
        } else if (!attributes.equals(other.attributes))
            return false;
        if (className == null) {
            if (other.className != null)
                return false;
        } else if (!className.equals(other.className))
            return false;
        return true;
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void marshall(OutputStream os) throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(this.getClass());
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(this, os);
    }

    public static <T> T unmarshal(String string, Class<T> clazz) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
        return (T) unmarshaller.unmarshal(new StringReader(string));
    }

    public static <T> T unmarshall(Class<T> t, String filePath) throws JAXBException, FileNotFoundException {
        JAXBContext context = JAXBContext.newInstance(t);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        FileInputStream fis = new FileInputStream(filePath);
        return (T) unmarshaller.unmarshal(fis);
    }

    public void toDOM(Document document, Element element) {

        if (className != null) {
            Element classNameElement = document.createElement("ClassName");
            classNameElement.appendChild(document.createTextNode(className));
            element.appendChild(classNameElement);
        }

        // The original XML mapping always creates <Attributes/>.
        Element attributesElement = document.createElement("Attributes");
        element.appendChild(attributesElement);

        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            Element attributeElement = document.createElement("Attribute");
            attributeElement.setAttribute("name", attribute.getKey());
            attributeElement.appendChild(document.createTextNode(attribute.getValue()));
            attributesElement.appendChild(attributeElement);
        }
    }

    public static void fromDOM(Element element, ResourceMessage resourceMessage) {

        NodeList classNameList = element.getElementsByTagName("ClassName");
        if (classNameList.getLength() > 0) {
            String value = classNameList.item(0).getTextContent();
            resourceMessage.setClassName(value);
        }

        NodeList attributesList = element.getElementsByTagName("Attributes");
        if (attributesList.getLength() > 0) {
            Element attributesElement = (Element) attributesList.item(0);

            NodeList attributeList = attributesElement.getElementsByTagName("Attribute");
            int attributeCount = attributeList.getLength();
            for (int i=0; i<attributeCount; i++) {
               Element attributeElement = (Element) attributeList.item(i);
               String name = attributeElement.getAttribute("name");
               String value = attributeElement.getTextContent();
               resourceMessage.setAttribute(name, value);
            }
        }
    }
}
