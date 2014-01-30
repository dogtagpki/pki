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

import org.jboss.resteasy.plugins.providers.atom.Link;

/**
 * @author Ade Lee
 */
@XmlRootElement(name="ResourceMessage")
public class ResourceMessage {

    protected Map<String, String> properties = new LinkedHashMap<String, String>();
    Link link;
    String className;

    public ResourceMessage() {
        // required for jax-b
    }

    public ResourceMessage(MultivaluedMap<String, String> form) {
        for (Map.Entry<String, List<String>> entry: form.entrySet()) {
            properties.put(entry.getKey(), entry.getValue().get(0));
        }
    }

    @XmlElement(name = "ClassName")
    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    @XmlElement(name = "Properties")
    @XmlJavaTypeAdapter(MapAdapter.class)
    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties.clear();
        this.properties.putAll(properties);
    }

    public Collection<String> getPropertyNames() {
        return properties.keySet();
    }

    public String getProperty(String name) {
        return properties.get(name);
    }

    public void setProperty(String name, String value) {
        properties.put(name, value);
    }

    public String removeProperty(String name) {
        return properties.remove(name);
    }

    public static class MapAdapter extends XmlAdapter<PropertyList, Map<String, String>> {

        public PropertyList marshal(Map<String, String> map) {
            PropertyList list = new PropertyList();
            for (Map.Entry<String, String> entry : map.entrySet()) {
                Property property = new Property();
                property.name = entry.getKey();
                property.value = entry.getValue();
                list.properties.add(property);
            }
            return list;
        }

        public Map<String, String> unmarshal(PropertyList list) {
            Map<String, String> map = new LinkedHashMap<String, String>();
            for (Property property : list.properties) {
                map.put(property.name, property.value);
            }
            return map;
        }
    }

    public static class PropertyList {
        @XmlElement(name = "Property")
        public List<Property> properties = new ArrayList<Property>();
    }

    public static class Property {

        @XmlAttribute
        public String name;

        @XmlValue
        public String value;
    }

    @XmlElement(name = "Link")
    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((link == null) ? 0 : link.hashCode());
        result = prime * result + ((properties == null) ? 0 : properties.hashCode());
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
        if (link == null) {
            if (other.link != null)
                return false;
        } else if (!link.equals(other.link))
            return false;
        if (properties == null) {
            if (other.properties != null)
                return false;
        } else if (!properties.equals(other.properties))
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
