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

package com.netscape.management.client.ug;

/**
 * Attribute search filter is used to display the available search attributes in the search dialog.
 * To add a searchable attribute in the search dialog, the developer needs to create a attribute
 * search filter object and add it to the search dialog plugin interface.
 *
 * @author  <a href=mailto:terencek@netscape.com>Terence Kwan</a>
 * @version 0.2 9/3/97
 */

public class AttributeSearchFilter {
    /**
      * Constructor for the attribtue search filter
      *
      * @param sID an unique id for the filter
      * @param sDisplayName display name for the filter
      * @param sAttributeName the assciated attribute name
      * @param sLDAPFilter LDAP filter
      */
    public AttributeSearchFilter(String sID, String sDisplayName,
            String sAttributeName, String sLDAPFilter) {
    }

    /**
      * set the filter ID
      *
      * @param sID id of the filter
      */
    public void setID(String sID) {
    }

    /**
      * set the display name
      *
      * @param sDisplay display name of the filter
      */
    public void setDisplayName(String sDisplayName) {
    }

    /**
      * set the attribute name
      *
      * @param sAttributeName directory server attribute name
      */
    public void setAttributeName(String sAttributeName) {
    }

    /**
      * set the LDAPFilter
      *
      * @param sLDAPFilter the LDAP filter for this attribute string
      */
    public void setLDAPFilter(String sLDAPFilter) {
    }

    /**
      * return the ID of the current filter
      *
      * @return the ID of the current filter
      */
    public String getID() {
        return "";
    }

    /**
      * return the filter display name
      *
      * @return display name
      */
    public String getDisplayName() {
        return "";
    }

    /**
      * return the attribute name of the filter
      *
      * @return attribute name of the filter
      */
    public String setAttributeName() {
        return "";
    }

    /**
      * return the filter string of the filter
      *
      * @return the filter string
      */
    public String getFilterString() {
        return "";
    }
}
