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

import netscape.security.util.*;

/**
 * Abstract class that converts a Ldap DN String to an X500Name, RDN or AVA 
 * and vice versa, except the string is a java string in unicode.
 * 
 * @author Lily Hsiao, Slava Galperin at Netscape Communications, Inc.
 */

public abstract class LdapDNStrConverter 
{
    // 
    // public parsing methods.
    //

    /**
     * Converts a Ldap DN string to a X500Name object.
     *
     * @param dn 	a Ldap DN String.
     *
     * @return 		an X500Name object for the Ldap DN String.
     */
    public abstract X500Name parseDN(String dn) 
	throws IOException;

	/**
	 * Like parseDN with a specified DER encoding order for Directory Strings.
	 */
    public abstract X500Name parseDN(String dn, byte[] tags) 
	throws IOException;

    /** 
     * Converts a Ldap DN string to a RDN object.
     * 
     * @param rdn 	a Ldap DN String 
     *
     * @return 		an RDN object.
     */
    public abstract RDN parseRDN(String rdn) 
	throws IOException;

	/**
	 * Like parseRDN with a specified DER encoding order for Directory Strings.
	 */
    public abstract RDN parseRDN(String rdn, byte[] tags) 
	throws IOException;

    /** 
     * Converts a Ldap DN string to a AVA object.
     *
     * @param ava 	a Ldap DN string.
     * @return 		an AVA object. 
     */
    public abstract AVA parseAVA(String ava) 
	throws IOException;

	/**
	 * Like parseAVA with a specified DER encoding order for Directory Strings.
	 */
    public abstract AVA parseAVA(String rdn, byte[] tags) 
	throws IOException;

    //
    // public encoding methods.
    //

    /**
     * Converts a X500Name object to a Ldap dn string.
     *
     * @param dn 	an X500Name object.
     * @return 		a Ldap DN String. 
     */
    public abstract String encodeDN(X500Name dn) throws IOException;

    /**
     * Converts an RDN object to a Ldap dn string.
     * 
     * @param rdn 	an RDN object.
     * @return 		a Ldap dn string.
     */
    public abstract String encodeRDN(RDN rdn) throws IOException;

    /**
     * Converts an AVA object to a Ldap dn string.
     * 
     * @param ava 	An AVA object.
     * @return 		A Ldap dn string.
     */
    public abstract String encodeAVA(AVA ava) throws IOException;

    //
    // public static methods
    //

    /**
     * Gets a global default Ldap DN String converter.
     * Currently it is LdapV3DNStrConverter object using the default
     * X500NameAttrMap and accepts unknown OIDs.
     * 
     * @see netscape.security.x509.LdapV3DNStrConverter
     *
     * @return    The global default LdapDNStrConverter instance.
     */
    public static LdapDNStrConverter getDefault()
    {
	return defaultConverter;
    }

    /**
     * Set the global default LdapDNStrConverter object.
     *
     * @param defConverter	A LdapDNStrConverter object to become
     *				the global default.
     */
    public static void setDefault(LdapDNStrConverter defConverter)
    {
	if (defConverter == null)
	    throw new IllegalArgumentException(
		"The default Ldap DN String converter cannot be set to null.");
	defaultConverter = defConverter;
    }

    //
    // private static variables
    //

    private static LdapDNStrConverter 
	    defaultConverter = new LdapV3DNStrConverter();
}
