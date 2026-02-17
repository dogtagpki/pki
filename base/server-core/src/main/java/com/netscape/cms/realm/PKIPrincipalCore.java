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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.realm;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collections;
import java.util.List;

/**
 * Container-agnostic PKI principal.
 *
 * This class implements java.security.Principal and carries user
 * information, authentication token, and roles without depending
 * on any container-specific classes (e.g. Tomcat's GenericPrincipal).
 *
 * Container-specific principal classes (such as PKIPrincipal for Tomcat)
 * wrap or delegate to this class.
 */
public class PKIPrincipalCore implements Principal, Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;
    private final String password;
    private final List<String> roles;
    private Object user;
    private Object authToken;

    public PKIPrincipalCore(String name, String password, List<String> roles) {
        this(name, password, roles, null, null);
    }

    public PKIPrincipalCore(String name, String password, List<String> roles,
            Object user, Object authToken) {
        this.name = name;
        this.password = password;
        this.roles = roles != null ? Collections.unmodifiableList(roles) : Collections.emptyList();
        this.user = user;
        this.authToken = authToken;
    }

    @Override
    public String getName() {
        return name;
    }

    public String getPassword() {
        return password;
    }

    public List<String> getRolesList() {
        return roles;
    }

    public String[] getRoles() {
        return roles.toArray(new String[0]);
    }

    public Object getUser() {
        return user;
    }

    public void setUser(Object user) {
        this.user = user;
    }

    public Object getAuthToken() {
        return authToken;
    }

    public void setAuthToken(Object authToken) {
        this.authToken = authToken;
    }

    @Override
    public String toString() {
        return "PKIPrincipalCore[" + name + "]";
    }
}
