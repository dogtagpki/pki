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
package com.netscape.certsrv.property;

import java.util.Locale;

/**
 * This interface represents a property descriptor.
 *
 * @version $Revision$, $Date$
 */
public interface IDescriptor {

    // syntax
    public static String DATE = "date";
    public static String PASSWORD = "password";
    public static String PRETTY_PRINT = "pretty_print";
    public static String IMAGE_URL = "image_url";
    public static String INTEGER = "integer";
    public static String BOOLEAN = "boolean";
    public static String STRING = "string";
    public static String STRING_LIST = "string_list";
    public static String KEYGEN_REQUEST = "keygen_request";
    public static String KEYGEN_REQUEST_TYPE = "keygen_request_type";
    public static String ENC_KEYGEN_REQUEST = "enc_keygen_request";
    public static String ENC_KEYGEN_REQUEST_TYPE = "enc_keygen_request_type";
    public static String SIGN_KEYGEN_REQUEST = "sign_keygen_request";
    public static String SIGN_KEYGEN_REQUEST_TYPE = "sign_keygen_request_type";
    public static String DUAL_KEYGEN_REQUEST = "dual_keygen_request";
    public static String DUAL_KEYGEN_REQUEST_TYPE = "dual_keygen_request_type";
    public static String CERT_REQUEST = "cert_request";
    public static String CERT_REQUEST_TYPE = "cert_request_type";
    public static String CHOICE = "choice"; // choice of strings
    public static String DN = "dn";
    public static String IP = "ip";
    public static String EMAIL = "email";

    // constraint
    public static String READONLY = "readonly";
    public static String HIDDEN = "hidden";

    /**
     * Returns the syntax of the property.
     *
     * @return syntax
     */
    public String getSyntax();

    /**
     * Constraint for the given syntax. For example,
     * - number(1-5): 1-5 is the constraint, and it indicates
     * that the number must be in the range of 1 to 5.
     * - choice(cert,crl): cert,crl is the constraint
     * for choice
     * If null, no constraint shall be enforced.
     *
     * @return constraint
     */
    public String getConstraint();

    /**
     * Retrieves the description of the property.
     *
     * @param locale user locale
     * @return localized description
     */
    public String getDescription(Locale locale);

    /**
     * Retrieves the default value of the property.
     *
     * @return default value
     */
    public String getDefaultValue();
}
