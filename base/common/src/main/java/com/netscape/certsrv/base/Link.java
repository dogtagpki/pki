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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---/**
package com.netscape.certsrv.base;

import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.util.Objects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "Link")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class Link {
    private String relationship;
    private String href;
    private String type;

    public Link() {
        // required for jaxb
    }

    public Link(String relationship, String href, String type) {
        this.relationship = relationship;
        this.href = href;
        this.type = type;
    }

    public Link(String relationship, URI uri) {
        this.relationship = relationship;
        this.href = uri.toString();
        this.type = "application/xml";
    }

    /**
     * @return the relationship
     */
    @XmlAttribute(name = "rel")
    public String getRelationship() {
        return relationship;
    }

    /**
     * @param relationship the relationship to set
     */
    public void setRelationship(String relationship) {
        this.relationship = relationship;
    }

    /**
     * @return the href
     */
    @XmlAttribute
    public String getHref() {
        return href;
    }

    /**
     * @param href the href to set
     */
    public void setHref(String href) {
        this.href = href;
    }

    /**
     * @return the type
     */
    @XmlAttribute
    public String getType() {
        return type;
    }

    /**
     * @param type the type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(Link.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static Link fromXML(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(Link.class).createUnmarshaller();
        return (Link) unmarshaller.unmarshal(new StringReader(string));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static Link fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, Link.class);
    }

    @Override
    public int hashCode() {
        return Objects.hash(href, relationship, type);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Link other = (Link) obj;
        return Objects.equals(href, other.href) &&
                Objects.equals(relationship, other.relationship) &&
                Objects.equals(type, other.type);
    }

}
