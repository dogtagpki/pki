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
package com.netscape.certsrv.dbs;




/**
 * An interface represents a filter converter
 * that understands how to convert a attribute
 * type from one defintion to another.
 * For example, 
 * <PRE>
 * (1) database layer need to convert
 *     registered attribute type to ldap attribute
 *     type.
 * (2) high level subsystem need to convert
 *     locale specific attribute type to registered
 *     attribute type.
 * </PRE>
 * 
 * @version $Revision$, $Date$ 
 */
public interface IFilterConverter {

    /**
     * Converts attribute into LDAP attribute.
     *
     * @param attr attribute name
     * @param op attribute operation
     * @param value attribute value
     * @return The LDAP attribute
     */
    public String convert(String attr, String op, String value);
}
