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
package com.netscape.certsrv.authentication;


import java.util.*;
import java.lang.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authentication.*;


/**
 * This class represents a registered authentication manager plugin.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class AuthMgrPlugin {
    protected String mId = null;
    protected String mClassPath = null;
    protected Class mClass = null;
    protected boolean mVisible = true;

    /**
     * Constructs a AuthManager plugin.
     * @param id auth manager implementation name
     * @param classPath class path
     */
    public AuthMgrPlugin(String id, String classPath) {

        /*
         if (id == null || classPath == null)
         throw new AssertionException("Authentication Manager id or classpath can't be null");
         */
        mId = id;
        mClassPath = classPath;
    }
		
    /**
     * Returns an auth manager implementation name
     * @return an auth manager implementation name
     */
    public String getId() {
        return mId;
    }

    /**
     * Returns a classpath of a AuthManager plugin
     * @return a classpath of a AuthManager plugin
     */
    public String getClassPath() {
        return mClassPath;
    }

    /** 
     * Returns a visibility of the plugin
     * @return a visibility of the plugin
     */
    public boolean isVisible() {
        return mVisible;
    }

    /** 
     * Sets visibility of the plugin
     * @param visibility visibility of the plugin
     */
    public void setVisible(boolean visibility) {
        mVisible = visibility;
    }
}
