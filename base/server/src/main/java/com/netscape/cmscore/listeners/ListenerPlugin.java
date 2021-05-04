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
package com.netscape.cmscore.listeners;

/**
 * This class represents a registered listener plugin.
 * <P>
 *
 * @author stevep
 * @version $Revision$, $Date$
 */
public class ListenerPlugin {
    protected String mId = null;
    protected String mClassPath = null;
    protected Class<?> mClass = null;

    /**
     * Constructs a Listener plugin.
     *
     * @param id listener implementation name
     * @param classPath class path
     */
    public ListenerPlugin(String id, String classPath) {
        //        if (id == null || classPath == null)
        //           throw new AssertionException("Listener id or classpath can't be null");
        mId = id;
        mClassPath = classPath;
    }

    public String getId() {
        return mId;
    }

    public String getClassPath() {
        return mClassPath;
    }
}
