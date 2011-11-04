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




/**
 * This represents a generici CMS plugin.
 * <p>
 * 
 * @version $Revision$, $Date$
 */
public class Plugin {

    private String mId = null;
    private String mClassPath = null;

    /**
     * Constructs a plugin.
     * 
     * @param id plugin implementation name
     * @param classPath class path
     */
    public Plugin(String id, String classPath) {
        mId = id;
        mClassPath = classPath;
    }
		
    /**
     * Returns the plugin identifier.
     *
     * @return plugin id
     */
    public String getId() {
        return mId;
    }

    /**
     * Returns the plugin classpath.
     *
     * @return plugin classpath
     */
    public String getClassPath() {
        return mClassPath;
    }
}
