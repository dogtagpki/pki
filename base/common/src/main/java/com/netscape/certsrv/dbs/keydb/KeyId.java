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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.dbs.keydb;

import java.math.BigInteger;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonValue;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * The KeyId class represents the identifier for a particular
 * key record. This identifier may be used to retrieve the key record
 * from the database.
 * <p>
 *
 * @author Endi S. Dewata
 * @version $Revision$ $Date$
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KeyId implements JSONSerializer {

    protected byte[] value;

    /**
     * Creates a new KeyId from its string representation.
     *
     * @param id a string containing the decimal or hex value for the identifier.
     */
    public KeyId(String id) {

        if (id == null) {
            throw new IllegalArgumentException("Missing key ID");
        }

        id = id.trim();

        if (!id.startsWith("0x")) { // decimal
            value = new BigInteger(id).toByteArray();
            return;
        }

        // hex
        id = id.substring(2);

        try {
            value = Hex.decodeHex(id);
        } catch (DecoderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates a new KeyId from its byte array representation.
     *
     * @param bytes a byte array containing the identifier.
     */
    public KeyId(byte[] bytes) {
        value = bytes;
    }

    /**
     * Creates a new KeyId from its BigInteger representation.
     *
     * @param id a BigInteger containing the identifier.
     */
    public KeyId(BigInteger id) {
        value = id.toByteArray();
    }

    /**
     * Creates a new KeyId from its integer representation.
     *
     * @param id an integer containing the identifier.
     */
    public KeyId(int id) {
        value = BigInteger.valueOf(id).toByteArray();
    }

    /**
     * Converts the KeyId into its BigInteger representation.
     *
     * @return a BigInteger containing the identifier.
     */
    public BigInteger toBigInteger() {
        return new BigInteger(value);
    }

    /**
     * Converts the KeyId into its string representation. The string
     * form can be stored in a database (such as the LDAP directory)
     *
     * @return a string containing the decimal (base 10) value for the identifier.
     */
    @Override
    public String toString() {
        return toBigInteger().toString();
    }

    /**
     * Converts the KeyId into its hex string representation. The string
     * form can be stored in a database (such as the LDAP directory)
     *
     * @return a string containing the hex (hex 16) value for the identifier.
     */
    @JsonValue
    public String toHexString() {
        return "0x" + Hex.encodeHexString(value);
    }

    /**
     * Converts the KeyId into its byte array representation.
     *
     * @return a byte array containing the identifier.
     */
    public byte[] toByteArray() {
        return value;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(value);
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
        KeyId other = (KeyId) obj;
        if (!Arrays.equals(value, other.value))
            return false;
        return true;
    }
}
