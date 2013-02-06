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

    @XmlElement(name="Subsystem")
    public SecurityDomainSubsystem[] getSubsystems() {
        return subsystems.values().toArray(new SecurityDomainSubsystem[subsystems.size()]);
    }

    public void setSubsystems(SecurityDomainSubsystem[] subsystems) {
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
    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            Marshaller marshaller = JAXBContext.newInstance(DomainInfo.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static DomainInfo valueOf(String string) throws Exception {
        try {
            Unmarshaller unmarshaller = JAXBContext.newInstance(DomainInfo.class).createUnmarshaller();
            return (DomainInfo)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
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

        DomainInfo before = new DomainInfo();
        before.setName("EXAMPLE");

        SecurityDomainHost host = new SecurityDomainHost();
        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");

        before.addHost("CA", host);

        String string = before.toString();
        System.out.println(string);

        DomainInfo after = DomainInfo.valueOf(string);
        System.out.println(before.equals(after));
    }
}
