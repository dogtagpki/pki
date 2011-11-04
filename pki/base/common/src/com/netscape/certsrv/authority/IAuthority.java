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
package com.netscape.certsrv.authority;


import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.request.IRequestListener;
import com.netscape.certsrv.request.IRequestQueue;


/**
 * Authority interface.
 *
 * @version $Revision$ $Date$
 */
public interface IAuthority extends ISubsystem {

    /**
     * Retrieves the request queue for the Authority.
     * <P>
     * @return the request queue.
     */
    public IRequestQueue getRequestQueue();

    /**
     * Registers request completed class.
     */
    public void registerRequestListener(IRequestListener listener);

    /**
     * Registers pending request class.
     */
    public void registerPendingListener(IRequestListener listener);

    /**
     * log interface
     */
    public void log(int level, String msg);

    /**
     * nickname of signing (id) cert
     */
    public String getNickname();

    /**
     * return official product name.
     */
    public String getOfficialName();

}
