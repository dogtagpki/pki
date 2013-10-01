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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.tps.profile;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
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
 * @author Endi S. Dewata
 */
@XmlRootElement(name="ProfileMapping")
public class ProfileMappingData {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(ProfileMappingData.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(ProfileMappingData.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    String id;
    String status;
    Map<String, String> properties = new LinkedHashMap<String, String>();

    Link link;

    @XmlAttribute(name="id")
    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    @XmlElement(name="Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @XmlElement(name="Properties")
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
        @XmlElement(name="Property")
        public List<Property> properties = new ArrayList<Property>();
    }

    public static class Property {

        @XmlAttribute
        public String name;

        @XmlValue
        public String value;
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
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((link == null) ? 0 : link.hashCode());
        result = prime * result + ((properties == null) ? 0 : properties.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
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
        ProfileMappingData other = (ProfileMappingData) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
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
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static ProfileMappingData valueOf(String string) throws Exception {
        try {
            return (ProfileMappingData)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        ProfileMappingData before = new ProfileMappingData();
        before.setID("profileMapping1");
        before.setStatus("ENABLED");
        before.setProperty("param1", "value1");
        before.setProperty("param2", "value2");

        String string = before.toString();
        System.out.println(string);

        ProfileMappingData after = ProfileMappingData.valueOf(string);
        System.out.println(before.equals(after));
    }
}
