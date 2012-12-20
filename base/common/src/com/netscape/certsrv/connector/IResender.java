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
package com.netscape.certsrv.connector;

import com.netscape.certsrv.request.IRequest;

/**
 * Resend requests at intervals to the server to ensure completion of requests.
 * Default interval is 5 minutes. The need to resend a message could arise
 * due to an error or the fact that the message could not be serviced
 * immediately.
 *
 * @version $Revision$, $Date$
 */
public interface IResender extends Runnable {

    /**
     * Adds the request to the resend queue.
     *
     * @param r Request to be placed on the resend queue.
     */
    public void addRequest(IRequest r);

    public void start(final String name);

    public void stop();
}
