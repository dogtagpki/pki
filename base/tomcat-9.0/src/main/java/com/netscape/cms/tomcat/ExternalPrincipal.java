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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.tomcat;

import org.apache.catalina.realm.GenericPrincipal;

import java.util.List;
import java.util.HashMap;

/**
 * Principal that carries additional request attributes.
 */
public class ExternalPrincipal extends GenericPrincipal {

    private HashMap<String, Object> attributes;

    public ExternalPrincipal(String name, String password, List<String> roles,
            HashMap<String, Object> attributes) {
        super(name, password, roles);
        this.attributes = attributes;
    }

    public HashMap<String, Object> getAttributes() {
        return attributes;
    }

}
