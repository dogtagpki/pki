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
package com.netscape.certsrv.logging;

import java.util.ListResourceBundle;
import java.util.ResourceBundle;

import com.netscape.certsrv.base.BaseResources;

/**
 * This is the fallback resource bundle for all log events.
 * <P>
 *
 * @version $Revision$, $Date$
 * @see java.util.ListResourceBundle
 */
public class LogResources extends ListResourceBundle {
    public static final String BASE_RESOURCES = BaseResources.class.getName();

    /**
     * Contructs a log resource bundle and sets it's parent to the base
     * resource bundle.
     *
     * @see com.netscape.certsrv.base.BaseResources
     */
    public LogResources() {
        super();
        setParent(ResourceBundle.getBundle(BASE_RESOURCES));
    }

    /**
     * Returns the content of this resource.
     *
     * @return Array of objects making up the contents of this resource.
     */
    public Object[][] getContents() {
        return contents;
    }

    /*
     * Contents.
     */

    static final Object[][] contents = {};
}
