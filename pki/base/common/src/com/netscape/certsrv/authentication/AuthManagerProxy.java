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

/**
 * A class represents an authentication manager. It contains an authentication
 * manager instance and its state (enable or not).
 * 
 * @version $Revision$, $Date$
 */
public class AuthManagerProxy {
    private boolean mEnable;
    private IAuthManager mMgr;

    /**
     * Constructor
     * 
     * @param enable true if the authMgr is enabled; false otherwise
     * @param mgr authentication manager instance
     */
    public AuthManagerProxy(boolean enable, IAuthManager mgr) {
        mEnable = enable;
        mMgr = mgr;
    }

    /**
     * Returns the state of the authentication manager instance
     * 
     * @return true if the state of the authentication manager instance is
     *         enabled; false otherwise.
     */
    public boolean isEnable() {
        return mEnable;
    }

    /**
     * Returns an authentication manager instance.
     * 
     * @return an authentication manager instance
     */
    public IAuthManager getAuthManager() {
        return mMgr;
    }
}
