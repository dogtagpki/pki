package com.netscape.certsrv.base;

import java.io.StringReader;
import java.io.StringWriter;
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
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author Ade Lee
 */
@XmlRootElement(name="ResourceMessage")
public class ResourceMessage {

    protected Map<String, String> attributes = new LinkedHashMap<String, String>();
    String className;

    public ResourceMessage() {
        // required for jax-b
    }

    public ResourceMessage(MultivaluedMap<String, String> form) {
        for (Map.Entry<String, List<String>> entry: form.entrySet()) {
            attributes.put(entry.getKey(), entry.getValue().get(0));
        }
    }

    @XmlElement(name = "ClassName")
    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    @XmlElement(name = "Attributes")
    @XmlJavaTypeAdapter(MapAdapter.class)
    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes.clear();
        this.attributes.putAll(attributes);
    }

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

    public static class MapAdapter extends XmlAdapter<AttributeList, Map<String, String>> {

        public AttributeList marshal(Map<String, String> map) {
            AttributeList list = new AttributeList();
            for (Map.Entry<String, String> entry : map.entrySet()) {
                Attribute attribute = new Attribute();
                attribute.name = entry.getKey();
                attribute.value = entry.getValue();
                list.attrs.add(attribute);
            }
            return list;
        }

        public Map<String, String> unmarshal(AttributeList list) {
            Map<String, String> map = new LinkedHashMap<String, String>();
            for (Attribute attribute : list.attrs) {
                map.put(attribute.name, attribute.value);
            }
            return map;
        }
    }

    public static class AttributeList {
        @XmlElement(name = "Attribute")
        public List<Attribute> attrs = new ArrayList<Attribute>();
    }

    public static class Attribute {

        @XmlAttribute
        public String name;

        @XmlValue
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

    public static <T> String marshal(T object, Class<T> clazz) throws JAXBException {
        Marshaller marshaller = JAXBContext.newInstance(clazz).createMarshaller();
        StringWriter sw = new StringWriter();
        marshaller.marshal(object, sw);
        return sw.toString();
    }

    @SuppressWarnings("unchecked")
    public static <T> T unmarshal(String string, Class<T> clazz) throws Exception {
        try {
            Unmarshaller unmarshaller = JAXBContext.newInstance(clazz).createUnmarshaller();
            return (T) unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

}
