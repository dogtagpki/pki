package com.netscape.certsrv.base;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * This is a base class for some REST request/response messages.
 *
 * JSON mapping:
 *
 * <pre>{@Code
 * {
 *     "Attributes": {
 *         "Attribute": [
 *             {
 *                 "name": ...,
 *                 "value": ...
 *             },
 *             ...
 *         ]
 *     },
 *     "ClassName": ...
 * }
 * }</pre>
 *
 * XML mapping:
 *
 * <pre>{@Code
 * <ResourceMessage>
 *     <Attributes>
 *         <Attribute name="...">...</Attribute>
 *         ...
 *     </Attributes>
 *     <ClassName>...</ClassName>
 * </ResourceMessage>
 * }</pre>
 *
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

    @XmlElement(name = "ClassName")
    @JsonProperty("ClassName")
    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    @XmlElement(name = "Attributes")
    @XmlJavaTypeAdapter(MapAdapter.class)
    @JsonIgnore
    public Map<String, String> getAttributes() {
        return attributes;
    }

    public void setAttributes(Map<String, String> attributes) {
        this.attributes.clear();
        this.attributes.putAll(attributes);
    }

    @JsonProperty("Attributes")
    public AttributeList getAttributeList() {
        AttributeList list = new AttributeList();
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            Attribute attribute = new Attribute();
            attribute.name = entry.getKey();
            attribute.value = entry.getValue();
            list.attrs.add(attribute);
        }
        return list;
    }

    public void setAttributeList(AttributeList list) {
        attributes.clear();
        for (Attribute attribute : list.attrs) {
            attributes.put(attribute.name, attribute.value);
        }
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
            Map<String, String> map = new LinkedHashMap<>();
            for (Attribute attribute : list.attrs) {
                map.put(attribute.name, attribute.value);
            }
            return map;
        }
    }

    @JsonSerialize(using=AttributeListSerializer.class)
    @JsonDeserialize(using=AttributeListDeserializer.class)
    public static class AttributeList {
        @XmlElement(name = "Attribute")
        @JsonProperty("Attribute")
        public List<Attribute> attrs = new ArrayList<>();
    }

    public static class Attribute {

        @XmlAttribute
        public String name;

        @XmlValue
        public String value;
    }

    public static class AttributeListSerializer extends StdSerializer<AttributeList> {

        public AttributeListSerializer() {
            this(null);
        }

        public AttributeListSerializer(Class<AttributeList> t) {
            super(t);
        }

        @Override
        public void serialize(
                AttributeList attributes,
                JsonGenerator generator,
                SerializerProvider provider
                ) throws IOException, JsonProcessingException {

            generator.writeStartObject();

            generator.writeArrayFieldStart("Attribute");
            for (Attribute attribute : attributes.attrs) {
                generator.writeStartObject();
                generator.writeStringField("name", attribute.name);
                generator.writeStringField("value", attribute.value);
                generator.writeEndObject();
            }
            generator.writeEndArray();

            generator.writeEndObject();
        }
    }

    public static class AttributeListDeserializer extends StdDeserializer<AttributeList> {

        public AttributeListDeserializer() {
            this(null);
        }

        public AttributeListDeserializer(Class<?> vc) {
            super(vc);
        }

        @Override
        public AttributeList deserialize(
                JsonParser parser,
                DeserializationContext context
                ) throws IOException, JsonProcessingException {

            AttributeList list = new AttributeList();

            JsonNode node = parser.getCodec().readTree(parser);
            JsonNode attributeNode = node.get("Attribute");

            for (JsonNode attr : attributeNode) {
                Attribute attribute = new Attribute();
                attribute.name = attr.get("name").asText();
                attribute.value = attr.get("value").asText();
                list.attrs.add(attribute);
            }

            return list;
        }
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

    public Element toDOM(Document document) {
        Element element = document.createElement("ResourceMessage");
        toDOM(document, element);
        return element;
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

    public static ResourceMessage fromDOM(Element element) {
        ResourceMessage resourceMessage = new ResourceMessage();
        fromDOM(element, resourceMessage);
        return resourceMessage;
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

    public static ResourceMessage fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element element = document.getDocumentElement();
        return fromDOM(element);
    }
}
