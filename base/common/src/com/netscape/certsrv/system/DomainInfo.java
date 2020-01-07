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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * @author alee
 */
@XmlRootElement(name="DomainInfo")
@XmlAccessorType(XmlAccessType.NONE)
public class DomainInfo {

    String name;
    Map<String, SecurityDomainSubsystem> subsystems = new LinkedHashMap<String, SecurityDomainSubsystem>();

    @XmlAttribute(name="id")
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @XmlElement(name="subsystems")
    public Map<String, SecurityDomainSubsystem> getSubsystems() {
        return subsystems;
    }

    public void setSubsystems(Map<String, SecurityDomainSubsystem> subsystems) {
        this.subsystems.clear();
        this.subsystems.putAll(subsystems);
    }

    @XmlElement(name="Subsystem")
    @JsonProperty("Subsystem")
    public SecurityDomainSubsystem[] getSubsystemArray() {
        return subsystems.values().toArray(new SecurityDomainSubsystem[subsystems.size()]);
    }

    public void setSubsystemArray(SecurityDomainSubsystem[] subsystems) {
        this.subsystems.clear();
        for (SecurityDomainSubsystem subsystem : subsystems) {
            this.subsystems.put(subsystem.name, subsystem);
        }
    }

    public SecurityDomainSubsystem getSubsystem(String type) {
        return subsystems.get(type);
    }

    public void addSubsystem(SecurityDomainSubsystem subsystem) {
        subsystems.put(subsystem.getName(), subsystem);
    }

    public void removeSubsystem(String type) {
        subsystems.remove(type);
    }

    public void addHost(String type, SecurityDomainHost host) {
        SecurityDomainSubsystem subsystem = getSubsystem(type);
        if (subsystem == null) {
            subsystem = new SecurityDomainSubsystem();
            subsystem.setName(type);
            addSubsystem(subsystem);
        }
        subsystem.addHost(host);
    }

    public void removeHost(String type, String hostId) {
        SecurityDomainSubsystem subsystem = getSubsystem(type);
        if (subsystem == null) return;
        subsystem.removeHost(hostId);
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        return mapper.writeValueAsString(this);
    }

    public static DomainInfo fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, DomainInfo.class);
    }

    public String toXML() throws Exception {
        StringWriter sw = new StringWriter();
        Marshaller marshaller = JAXBContext.newInstance(DomainInfo.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static DomainInfo fromXML(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(DomainInfo.class).createUnmarshaller();
        return (DomainInfo)unmarshaller.unmarshal(new StringReader(string));
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((subsystems == null) ? 0 : subsystems.hashCode());
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
        DomainInfo other = (DomainInfo) obj;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (subsystems == null) {
            if (other.subsystems != null)
                return false;
        } else if (!subsystems.equals(other.subsystems))
            return false;
        return true;
    }

    public static void main(String args[]) throws Exception {

        DomainInfo info = new DomainInfo();
        info.setName("EXAMPLE");

        SecurityDomainHost host = new SecurityDomainHost();
        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");

        info.addHost("CA", host);

        String xml = info.toXML();
        System.out.println(xml);

        DomainInfo afterXML = DomainInfo.fromXML(xml);
        System.out.println(info.equals(afterXML));

        String json = info.toJSON();
        System.out.println(json);

        DomainInfo afterJSON = DomainInfo.fromJSON(json);
        System.out.println(info.equals(afterJSON));
    }
}
