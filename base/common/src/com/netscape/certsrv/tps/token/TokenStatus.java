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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.tps.token;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.netscape.certsrv.tps.token.TokenStatus.TokenStatusAdapter;


/**
 * @author Endi S. Dewata
 */
@XmlJavaTypeAdapter(TokenStatusAdapter.class)
public class TokenStatus {

    public static class TokenStatusAdapter extends XmlAdapter<String, TokenStatus> {

        public String marshal(TokenStatus status) {
            return status.name;
        }

        public TokenStatus unmarshal(String status) {
            return TokenStatus.valueOf(status);
        }
    }

    static Map<String, TokenStatus> instancesByName = new HashMap<String, TokenStatus>();
    static Map<Integer, TokenStatus> instancesByValue = new HashMap<Integer, TokenStatus>();

    public final static int TOKEN_FORMATTED           = 0;
    public final static int TOKEN_DAMAGED             = 1;
    public final static int TOKEN_PERM_LOST           = 2;
    public final static int TOKEN_SUSPENDED           = 3;
    public final static int TOKEN_ACTIVE              = 4;
    public final static int TOKEN_TEMP_LOST_PERM_LOST = 5;
    public final static int TOKEN_TERMINATED          = 6;
    public final static int TOKEN_UNFORMATTED         = 7;

    public final static TokenStatus FORMATTED           = new TokenStatus("FORMATTED", TOKEN_FORMATTED);
    public final static TokenStatus DAMAGED             = new TokenStatus("DAMAGED", TOKEN_DAMAGED);
    public final static TokenStatus PERM_LOST           = new TokenStatus("PERM_LOST", TOKEN_PERM_LOST);
    public final static TokenStatus SUSPENDED           = new TokenStatus("SUSPENDED", TOKEN_SUSPENDED);
    public final static TokenStatus ACTIVE              = new TokenStatus("ACTIVE", TOKEN_ACTIVE);
    public final static TokenStatus TEMP_LOST_PERM_LOST = new TokenStatus("TEMP_LOST_PERM_LOST", TOKEN_TEMP_LOST_PERM_LOST);
    public final static TokenStatus TERMINATED          = new TokenStatus("TERMINATED", TOKEN_TERMINATED);
    public final static TokenStatus UNFORMATTED         = new TokenStatus("UNFORMATTED", TOKEN_UNFORMATTED);

    String name;
    Integer value;

    public TokenStatus() {
        // required for JAXB
    }

    TokenStatus(String name, Integer value) {
        this.name = name;
        this.value = value;

        instancesByName.put(name, this);
        instancesByValue.put(value, this);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Integer getValue() {
        return value;
    }

    public void setValue(Integer value) {
        this.value = value;
    }

    public String toString() {
        return name;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
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
        TokenStatus other = (TokenStatus) obj;
        if (name == null) {
            if (other.name != null)
                return false;
        } else if (!name.equals(other.name))
            return false;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }

    public static Collection<TokenStatus> values() {
        return instancesByName.values();
    }

    public static TokenStatus valueOf(String name) {

        if ("UNINITIALIZED".equals(name)) {
            System.err.println("WARNING: The token status " + name + " has been deprecated. Please use " + FORMATTED + " instead.");
            return FORMATTED;
        }

        if ("TEMP_LOST".equals(name)) {
            System.err.println("WARNING: The token status " + name + " has been deprecated. Please use " + SUSPENDED + " instead.");
            return SUSPENDED;
        }

        TokenStatus status = instancesByName.get(name);

        if (status == null) {
            throw new IllegalArgumentException("Invalid token status name: " + name);
        }

        return status;
    }

    public static TokenStatus fromInt(Integer value) {

        TokenStatus status = instancesByValue.get(value);

        if (status == null) {
            throw new IllegalArgumentException("Invalid token status value: " + value);
        }

        return status;
    }
}
