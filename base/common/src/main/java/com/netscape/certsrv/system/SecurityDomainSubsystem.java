/**
 *
 */
package com.netscape.certsrv.system;

import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
 public class SecurityDomainSubsystem implements JSONSerializer {

    String name;
    Map<String, SecurityDomainHost> hosts = new LinkedHashMap<>();

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Map<String, SecurityDomainHost> getHosts() {
        return hosts;
    }

    public void setHosts(Map<String, SecurityDomainHost> hosts) {
        this.hosts.clear();
        this.hosts.putAll(hosts);
    }

    /**
     * @return the hosts
     */
    @JsonProperty("Host")
    public SecurityDomainHost[] getHostArray() {
        return hosts.values().toArray(new SecurityDomainHost[hosts.size()]);
    }

    /**
     * @param hosts the system to set
     */
    public void setHostArray(SecurityDomainHost[] hosts) {
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

}
