/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.acl;

import java.util.Enumeration;

/**
 * LdapACLSelector is an interface for ACL selection from
 * multi-valued LDAP aci attributes.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 3/15/97
 * @see LdapACL
 * @see ACL
 */
public interface LdapACLSelector {
    /**
      * When a multi-valued aci attribute is found, this function
      * is called with an Enumeration of the String values.
      * This function should return the String of the value
      * to be used by the LdapACL instance.
      *
      * @param acl the referenced ACL
      * @param stringValueEnumeration an Enumeration of the
      *  String values of the aci attribute.
      * @return the String value of the selected value, or null
      *  if no value is selected.
      */
    public String select(LdapACL acl, Enumeration stringValueEnumeration);

    /**
     * Called on exception during ACL loading.
     *
     * @param acl the referenced ACL
     * @param e the Exception
     */
    public void error(LdapACL acl, Exception e);
}
