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
public class DomainInfo implements JSONSerializer {

    @JsonProperty("id")
    String name;

    @JsonProperty("subsystems")
    Map<String, SecurityDomainSubsystem> subsystems = new LinkedHashMap<>();

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Map<String, SecurityDomainSubsystem> getSubsystems() {
        return subsystems;
    }

    public void setSubsystems(Map<String, SecurityDomainSubsystem> subsystems) {
        this.subsystems.clear();
        this.subsystems.putAll(subsystems);
    }

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

}
