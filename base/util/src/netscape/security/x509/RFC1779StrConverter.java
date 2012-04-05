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
package netscape.security.x509;

import java.io.IOException;

import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * Converts a RFC 1779 string to a X500Name, RDN or AVA object and vice versa.
 *
 * @see LdapDNStrConverter
 * @see LdapV3DNStrConverter
 *
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 */

public class RFC1779StrConverter extends LdapV3DNStrConverter {
    //
    // Constructors.
    //

    /**
     * Constructs a RFC1779StrConverter using the global default
     * X500NameAttrMap and accepts OIDs not listed in the attribute map.
     */
    public RFC1779StrConverter() {
        super();
    }

    /**
     * Constructs a RFC1779StrConverter using the specified X500NameAttrMap
     * and boolean for whether to accept OIDs not in the X500NameAttrMap.
     *
     * @param attributeMap A X500NameAttrMap to use for this converter.
     * @param doAcceptUnknownOids Accept unregistered attributes, i.e. OIDs
     *            not in the map).
     */
    public RFC1779StrConverter(X500NameAttrMap attributeMap,
                  boolean doAcceptUnknownOids) {
        super(attributeMap, doAcceptUnknownOids);
    }

    //
    // overriding methods.
    //

    /**
     * Converts a OID to a attribute keyword in a Ldap DN string or
     * to a "OID.1.2.3.4" string syntax as defined in RFC1779.
     *
     * @param oid an ObjectIdentifier.
     *
     * @return a attribute keyword or "OID.1.2.3.4" string.
     *
     * @exception IOException if an error occurs during the conversion.
     */
    public String encodeOID(ObjectIdentifier oid)
            throws IOException {
        String keyword = attrMap.getName(oid);
        if (keyword == null)
            if (!acceptUnknownOids)
                throw new IllegalArgumentException("Unrecognized OID");
            else
                keyword = "OID" + "." + oid.toString();
        return keyword;
    }

    /**
     * Converts a attribute value as a DerValue to a string in a
     * RFC1779 Ldap DN string.
     *
     * @param attrValue an attribute value.
     * @param oid ObjectIdentifier for the attribute.
     * @return a string in RFC1779 syntax.
     * @exception IOException if an error occurs during the conversion.
     */
    public String encodeValue(DerValue attrValue, ObjectIdentifier oid)
            throws IOException {
        String s = super.encodeValue(attrValue, oid);
        if (s.indexOf('\n') != -1)
            return "\"" + s + "\"";
        else
            return s;
    }
}
