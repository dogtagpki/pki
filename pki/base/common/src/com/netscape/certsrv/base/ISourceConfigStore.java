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


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Enumeration;


/**
 * An interface that represents the source that creates the configuration
 * store tree. Note that the tree can be built based on the information
 * from a text file or ldap entries.
 * @see com.netscape.certsrv.base.IConfigStore
 *
 * @version $Revision$, $Date$
 */
public interface ISourceConfigStore extends Serializable {

    /**
     * Gets a property.
     * <P>
     *
     * @param name The property name
     * @return property value
     */
    public String get(String name);

    /**
     * Retrieves a property.
     * <P>
     *
     * @param name The property name
     * @param value The property value
     */
    public String put(String name, String value);

    /**
     * Returns an enumeration of the config store's keys.
     * <P>
     *
     * @return a list of keys
     * @see java.util.Hashtable#elements
     * @see java.util.Enumeration
     */
    public Enumeration<String> keys();

    /**
     * Reads a config store from an input stream. 
     *
     * @param in input stream where the properties are located
     * @exception IOException If an IO error occurs while loading from input.
     */
    public void load(InputStream in) throws IOException;

    /**
     * Stores this config store to the specified output stream. 
     *
     * @param out output stream where the properties should be serialized
     * @param header optional header to be serialized
     */
    public void save(OutputStream out, String header);

}
