package com.netscape.certsrv.base;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.OutputStream;
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
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.SymKeyGenerationRequest;

/**
 * @author Ade Lee
 */
@XmlRootElement(name = "ResourceMessage")
@XmlSeeAlso({
    Account.class,
    KeyArchivalRequest.class,
    KeyRecoveryRequest.class,
    SymKeyGenerationRequest.class,
    PKIException.Data.class,
    AsymKeyGenerationRequest.class
})
@XmlAccessorType(XmlAccessType.NONE)
@JsonInclude(Include.NON_EMPTY)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ResourceMessage {

    protected Map<String, String> attributes = new LinkedHashMap<String, String>();
    String className;

    public ResourceMessage() {
        // required for jax-b
    }

    public ResourceMessage(MultivaluedMap<String, String> form) {
        for (Map.Entry<String, List<String>> entry : form.entrySet()) {
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

    public static class MapAdapter extends XmlAdapter<AttributeList, Map<String, String>> {

        @Override
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

        @Override
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
}
