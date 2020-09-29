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
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;

/**
 * An interface that defines abilities of request listener,
 *
 * @version $Revision$, $Date$
 */
public interface IRequestListener {

    /**
     * Initializes request listener for the specific subsystem
     * and configuration store.
     *
     * @param sub subsystem
     * @param config configuration store
     */
    public void init(ISubsystem sub, IConfigStore config) throws EBaseException;

    /**
     * Accepts request.
     *
     * @param request request
     */
    public void accept(IRequest request);

    /**
     * Sets attribute.
     *
     * @param name attribute name
     * @param val attribute value
     */
    public void set(String name, String val);
}
