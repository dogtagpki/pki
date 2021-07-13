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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class SecurityDomainHost implements JSONSerializer {

    protected String id;

    @JsonProperty("Hostname")
    protected String hostname;

    @JsonProperty("Port")
    protected String port;

    @JsonProperty("SecurePort")
    protected String securePort;

    @JsonProperty("SecureEEClientAuthPort")
    protected String secureEEClientAuthPort;

    @JsonProperty("SecureAgentPort")
    protected String secureAgentPort;

    @JsonProperty("SecureAdminPort")
    protected String secureAdminPort;

    @JsonProperty("Clone")
    protected String clone;

    @JsonProperty("SubsystemName")
    protected String subsystemName;

    @JsonProperty("DomainManager")
    protected String domainManager;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public String getSecurePort() {
        return securePort;
    }

    public void setSecurePort(String securePort) {
        this.securePort = securePort;
    }

    public String getSecureAgentPort() {
        return secureAgentPort;
    }

    public void setSecureAgentPort(String secureAgentPort) {
        this.secureAgentPort = secureAgentPort;
    }

    public String getSecureAdminPort() {
        return secureAdminPort;
    }

    public void setSecureAdminPort(String secureAdminPort) {
        this.secureAdminPort = secureAdminPort;
    }

    public String getSecureEEClientAuthPort() {
        return secureEEClientAuthPort;
    }

    public void setSecureEEClientAuthPort(String secureEEClientAuthPort) {
        this.secureEEClientAuthPort = secureEEClientAuthPort;
    }

    public String getClone() {
        return clone;
    }

    public void setClone(String clone) {
        this.clone = clone;
    }

    public String getSubsystemName() {
        return subsystemName;
    }

    public void setSubsystemName(String subsystemName) {
        this.subsystemName = subsystemName;
    }

    public String getDomainManager() {
        return domainManager;
    }

    public void setDomainManager(String domainManager) {
        this.domainManager = domainManager;
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

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
