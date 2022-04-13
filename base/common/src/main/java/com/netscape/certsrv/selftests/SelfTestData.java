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

package com.netscape.certsrv.selftests;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class SelfTestData implements JSONSerializer {

    String id;
    Boolean enabledAtStartup;
    Boolean criticalAtStartup;
    Boolean enabledOnDemand;
    Boolean criticalOnDemand;

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    public Boolean isEnabledAtStartup() {
        return enabledAtStartup;
    }

    public void setEnabledAtStartup(Boolean enabledAtStartup) {
        this.enabledAtStartup = enabledAtStartup;
    }

    public Boolean isCriticalAtStartup() {
        return criticalAtStartup;
    }

    public void setCriticalAtStartup(Boolean criticalAtStartup) {
        this.criticalAtStartup = criticalAtStartup;
    }

    public Boolean isEnabledOnDemand() {
        return enabledOnDemand;
    }

    public void setEnabledOnDemand(Boolean enabledOnDemand) {
        this.enabledOnDemand = enabledOnDemand;
    }

    public Boolean isCriticalOnDemand() {
        return criticalOnDemand;
    }

    public void setCriticalOnDemand(Boolean criticalOnDemand) {
        this.criticalOnDemand = criticalOnDemand;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((criticalOnDemand == null) ? 0 : criticalOnDemand.hashCode());
        result = prime * result + ((enabledOnDemand == null) ? 0 : enabledOnDemand.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
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
        SelfTestData other = (SelfTestData) obj;
        if (criticalOnDemand == null) {
            if (other.criticalOnDemand != null)
                return false;
        } else if (!criticalOnDemand.equals(other.criticalOnDemand))
            return false;
        if (enabledOnDemand == null) {
            if (other.enabledOnDemand != null)
                return false;
        } else if (!enabledOnDemand.equals(other.enabledOnDemand))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        return true;
    }

}
