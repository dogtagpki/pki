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
 *
 */
@XmlRootElement(name="SecurityDomainHost")
@XmlAccessorType(XmlAccessType.NONE)
public class SecurityDomainHost {

    protected String id;
    protected String hostname;
    protected String port;
    protected String securePort;
    protected String secureEEClientAuthPort;
    protected String secureAgentPort;
    protected String secureAdminPort;
    protected String clone;
    protected String subsystemName;
    protected String domainManager;

    @XmlAttribute(name="id")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @XmlElement(name="Hostname")
    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @XmlElement(name="Port")
    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    @XmlElement(name="SecurePort")
    public String getSecurePort() {
        return securePort;
    }

    public void setSecurePort(String securePort) {
        this.securePort = securePort;
    }

    @XmlElement(name="SecureAgentPort")
    public String getSecureAgentPort() {
        return secureAgentPort;
    }

    public void setSecureAgentPort(String secureAgentPort) {
        this.secureAgentPort = secureAgentPort;
    }

    @XmlElement(name="SecureAdminPort")
    public String getSecureAdminPort() {
        return secureAdminPort;
    }

    public void setSecureAdminPort(String secureAdminPort) {
        this.secureAdminPort = secureAdminPort;
    }

    @XmlElement(name="SecureEEClientAuthPort")
    public String getSecureEEClientAuthPort() {
        return secureEEClientAuthPort;
    }

    public void setSecureEEClientAuthPort(String secureEEClientAuthPort) {
        this.secureEEClientAuthPort = secureEEClientAuthPort;
    }

    @XmlElement(name="Clone")
    public String getClone() {
        return clone;
    }

    public void setClone(String clone) {
        this.clone = clone;
    }

    @XmlElement(name="SubsystemName")
    public String getSubsystemName() {
        return subsystemName;
    }

    public void setSubsystemName(String subsystemName) {
        this.subsystemName = subsystemName;
    }

    @XmlElement(name="DomainManager")
    public String getDomainManager() {
        return domainManager;
    }

    public void setDomainManager(String domainManager) {
        this.domainManager = domainManager;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            Marshaller marshaller = JAXBContext.newInstance(SecurityDomainHost.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SecurityDomainHost valueOf(String string) throws Exception {
        try {
            Unmarshaller unmarshaller = JAXBContext.newInstance(SecurityDomainHost.class).createUnmarshaller();
            return (SecurityDomainHost)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((clone == null) ? 0 : clone.hashCode());
        result = prime * result + ((domainManager == null) ? 0 : domainManager.hashCode());
        result = prime * result + ((hostname == null) ? 0 : hostname.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((port == null) ? 0 : port.hashCode());
        result = prime * result + ((secureAdminPort == null) ? 0 : secureAdminPort.hashCode());
        result = prime * result + ((secureAgentPort == null) ? 0 : secureAgentPort.hashCode());
        result = prime * result + ((secureEEClientAuthPort == null) ? 0 : secureEEClientAuthPort.hashCode());
        result = prime * result + ((securePort == null) ? 0 : securePort.hashCode());
        result = prime * result + ((subsystemName == null) ? 0 : subsystemName.hashCode());
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
        SecurityDomainHost other = (SecurityDomainHost) obj;
        if (clone == null) {
            if (other.clone != null)
                return false;
        } else if (!clone.equals(other.clone))
            return false;
        if (domainManager == null) {
            if (other.domainManager != null)
                return false;
        } else if (!domainManager.equals(other.domainManager))
            return false;
        if (hostname == null) {
            if (other.hostname != null)
                return false;
        } else if (!hostname.equals(other.hostname))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (port == null) {
            if (other.port != null)
                return false;
        } else if (!port.equals(other.port))
            return false;
        if (secureAdminPort == null) {
            if (other.secureAdminPort != null)
                return false;
        } else if (!secureAdminPort.equals(other.secureAdminPort))
            return false;
        if (secureAgentPort == null) {
            if (other.secureAgentPort != null)
                return false;
        } else if (!secureAgentPort.equals(other.secureAgentPort))
            return false;
        if (secureEEClientAuthPort == null) {
            if (other.secureEEClientAuthPort != null)
                return false;
        } else if (!secureEEClientAuthPort.equals(other.secureEEClientAuthPort))
            return false;
        if (securePort == null) {
            if (other.securePort != null)
                return false;
        } else if (!securePort.equals(other.securePort))
            return false;
        if (subsystemName == null) {
            if (other.subsystemName != null)
                return false;
        } else if (!subsystemName.equals(other.subsystemName))
            return false;
        return true;
    }

    public static void main(String args[]) throws Exception {

        SecurityDomainHost before = new SecurityDomainHost();
        before.setId("CA localhost 8443");
        before.setHostname("localhost");
        before.setPort("8080");
        before.setSecurePort("8443");

        String string = before.toString();
        System.out.println(string);

        SecurityDomainHost after = SecurityDomainHost.valueOf(string);
        System.out.println(before.equals(after));
    }
}
