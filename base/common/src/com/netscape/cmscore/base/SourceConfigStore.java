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
package com.netscape.cmscore.base;

import com.netscape.certsrv.base.ISourceConfigStore;

/**
 * This class is is a wrapper to hide the Properties methods from
 * the PropConfigStore. Lucky for us, Properties already implements
 * almost every thing ISourceConfigStore requires.
 *
 * @version $Revision$, $Date$
 * @see java.util.Properties
 */
public class SourceConfigStore extends SimpleProperties implements ISourceConfigStore {

    /**
     *
     */
    private static final long serialVersionUID = -1703553593020810628L;

    /**
     * Retrieves a property from the config store
     * <P>
     *
     * @param name property name
     * @return property value
     */
    public String get(String name) {
        return super.get(name); // from Properties->Hashtable
    }

    /**
     * Puts a property into the config store.
     * <P>
     *
     * @param name property name
     * @param value property value
     * @return
     */
    public String put(String name, String value) {
        return super.put(name, value); // from Properties->Hashtable
    }
}
