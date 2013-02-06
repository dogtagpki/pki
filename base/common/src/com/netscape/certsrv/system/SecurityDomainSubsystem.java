/**
 *
 */
package com.netscape.certsrv.system;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.LinkedHashMap;

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
@XmlRootElement(name="SecurityDomainSubsystem")
@XmlAccessorType(XmlAccessType.NONE)
 public class SecurityDomainSubsystem {

    String name;
    LinkedHashMap<String, SecurityDomainHost> hosts = new LinkedHashMap<String, SecurityDomainHost>();

    @XmlAttribute(name="id")
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the systems
     */
    @XmlElement(name="Host")
    public SecurityDomainHost[] getHosts() {
        return hosts.values().toArray(new SecurityDomainHost[hosts.size()]);
    }

    /**
     * @param hosts the systems to set
     */
    public void setHosts(SecurityDomainHost[] hosts) {
        this.hosts.clear();
        for (SecurityDomainHost host : hosts) {
            addHost(host);
        }
    }

    public void addHost(SecurityDomainHost host) {
        hosts.put(host.getId(), host);
    }

    public void removeHost(String hostId) {
        hosts.remove(hostId);
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            Marshaller marshaller = JAXBContext.newInstance(SecurityDomainSubsystem.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SecurityDomainSubsystem valueOf(String string) throws Exception {
        try {
            Unmarshaller unmarshaller = JAXBContext.newInstance(SecurityDomainSubsystem.class).createUnmarshaller();
            return (SecurityDomainSubsystem)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((hosts == null) ? 0 : hosts.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
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
        SecurityDomainSubsystem other = (SecurityDomainSubsystem) obj;
        if (hosts == null) {
            if (other.hosts != null)
                return false;
        } else if (!hosts.equals(other.hosts))
            return false;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        return true;
    }

    public static void main(String args[]) throws Exception {

        SecurityDomainSubsystem before = new SecurityDomainSubsystem();
        before.setName("CA");

        SecurityDomainHost host = new SecurityDomainHost();
        host.setId("CA localhost 8443");
        host.setHostname("localhost");
        host.setPort("8080");
        host.setSecurePort("8443");

        before.addHost(host);

        String string = before.toString();
        System.out.println(string);

        SecurityDomainSubsystem after = SecurityDomainSubsystem.valueOf(string);
        System.out.println(before.equals(after));
    }
}
