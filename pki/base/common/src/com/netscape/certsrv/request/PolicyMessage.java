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
package com.netscape.certsrv.request;


import com.netscape.certsrv.base.EBaseException;


/**
 * A (localizable) message recorded by a policy module that describes
 * the reason for rejecting a request.
 * <p>
 * @version $Revision$, $Date$
 */
public class PolicyMessage
    extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -8129371562473386912L;

    /**
     * Class constructor that registers policy message.
     * <p>
     * @param message message string
     */
    public PolicyMessage(String message) {
        super(message);
    }
}
