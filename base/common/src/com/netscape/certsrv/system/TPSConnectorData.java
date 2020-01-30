package com.netscape.certsrv.system;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;

@XmlRootElement(name="TPSConnectorData")
public class TPSConnectorData {

    String id;
    String host;
    String port;
    String userID;
    String nickname;

    Link link;

    @XmlAttribute(name="id")
    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    @XmlElement(name="Host")
    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    @XmlElement(name="Port")
    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    @XmlElement(name="UserID")
    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    @XmlElement(name="Nickname")
    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    @XmlElement(name="Link")
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
        result = prime * result + ((host == null) ? 0 : host.hashCode());
        result = prime * result + ((port == null) ? 0 : port.hashCode());
        result = prime * result + ((userID == null) ? 0 : userID.hashCode());
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
        TPSConnectorData other = (TPSConnectorData) obj;
        if (host == null) {
            if (other.host != null)
                return false;
        } else if (!host.equals(other.host))
            return false;
        if (port == null) {
            if (other.port != null)
                return false;
        } else if (!port.equals(other.port))
            return false;
        if (userID == null) {
            if (other.userID != null)
                return false;
        } else if (!userID.equals(other.userID))
            return false;
        return true;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(TPSConnectorData.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static TPSConnectorData fromXML(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(TPSConnectorData.class).createUnmarshaller();
        return (TPSConnectorData)unmarshaller.unmarshal(new StringReader(string));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        mapper.setSerializationInclusion(Include.NON_NULL);
        return mapper.writeValueAsString(this);
    }

    public static TPSConnectorData fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, TPSConnectorData.class);
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String args[]) throws Exception {

        TPSConnectorData before = new TPSConnectorData();
        before.setID("tps0");
        before.setUserID("user1");

        String xml = before.toXML();
        System.out.println("XML (before): " + xml);

        TPSConnectorData afterXML = TPSConnectorData.fromXML(xml);
        System.out.println("XML (after): " + afterXML);

        System.out.println(before.equals(afterXML));

        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        TPSConnectorData afterJSON = TPSConnectorData.fromJSON(json);
        System.out.println("JSON (after): " + json);

        System.out.println(before.equals(afterJSON));
    }
}
