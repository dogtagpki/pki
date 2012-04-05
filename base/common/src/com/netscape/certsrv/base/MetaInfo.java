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
package com.netscape.certsrv.base;

import java.util.Enumeration;
import java.util.Hashtable;

/**
 * A class represents meta information. A meta information
 * object is just a generic hashtable that is embedded into
 * a request object.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class MetaInfo implements IAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = 7722068404789828101L;
    public static final String REQUEST_ID = "requestId";
    public static final String IN_LDAP_PUBLISH_DIR = "inLdapPublishDir";

    private Hashtable<String, Object> content = new Hashtable<String, Object>();

    /**
     * Constructs a meta information.
     * <P>
     */
    public MetaInfo() {
    }

    /**
     * Returns a short string describing this certificate attribute.
     * <P>
     *
     * @return information about this certificate attribute.
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();

        sb.append("[\n");
        sb.append("  Meta information:\n");
        Enumeration<String> enum1 = content.keys();

        while (enum1.hasMoreElements()) {
            String key = (String) enum1.nextElement();

            sb.append("  " + key + " : " + content.get(key) + "\n");
        }
        sb.append("]\n");
        return sb.toString();
    }

    /**
     * Gets an attribute value.
     * <P>
     *
     * @param name the name of the attribute to return.
     * @exception EBaseException on attribute handling errors.
     */
    public Object get(String name) throws EBaseException {
        return content.get(name);
    }

    /**
     * Sets an attribute value.
     *
     * @param name the name of the attribute
     * @param obj the attribute object.
     *
     * @exception EBaseException on attribute handling errors.
     */
    public void set(String name, Object obj) throws EBaseException {
        content.put(name, obj);
    }

    /**
     * Deletes an attribute value from this CertAttrSet.
     * <P>
     *
     * @param name the name of the attribute to delete.
     * @exception EBaseException on attribute handling errors.
     */
    public void delete(String name) throws EBaseException {
        content.remove(name);
    }

    /**
     * Returns an enumeration of the names of the attributes existing within
     * this attribute.
     * <P>
     *
     * @return an enumeration of the attribute names.
     */
    public Enumeration<String> getElements() {
        return content.keys();
    }
}
