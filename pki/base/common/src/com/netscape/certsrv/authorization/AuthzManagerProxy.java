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
package com.netscape.certsrv.authorization;


/**
 * A class represents an authorization manager. It contains an
 * authorization manager instance and its state (enable or not).
 * @version $Revision$, $Date$
 */
public class AuthzManagerProxy {
    private boolean mEnable;
    private IAuthzManager mMgr;

    /**
     * Constructor
     * @param enable true if the authzMgr is enabled; false otherwise
     * @param mgr authorization manager instance
    */
    public AuthzManagerProxy(boolean enable, IAuthzManager mgr) {
        mEnable = enable;
        mMgr = mgr;
    }

    /**
     * Returns the state of the authorization manager instance
     * @return true if the state of the authorization manager instance is
     *         enabled; false otherwise.
     */
    public boolean isEnable() {
        return mEnable;
    }

    /**
     * Returns an authorization manager instance.
     * @return an authorization manager instance
     */
    public IAuthzManager getAuthzManager() {
        return mMgr;
    }
}
