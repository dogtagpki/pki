//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.profile;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfilePolicy implements JSONSerializer {

    private String id = null;
    private PolicyDefault def = null;
    private PolicyConstraint constraint = null;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public PolicyDefault getDef() {
        return def;
    }

    public void setDef(PolicyDefault def) {
        this.def = def;
    }

    public PolicyConstraint getConstraint() {
        return constraint;
    }

    public void setConstraint(PolicyConstraint constraint) {
        this.constraint = constraint;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((constraint == null) ? 0 : constraint.hashCode());
        result = prime * result + ((def == null) ? 0 : def.hashCode());
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
        ProfilePolicy other = (ProfilePolicy) obj;
        if (constraint == null) {
            if (other.constraint != null)
                return false;
        } else if (!constraint.equals(other.constraint))
            return false;
        if (def == null) {
            if (other.def != null)
                return false;
        } else if (!def.equals(other.def))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        return true;
    }

}
