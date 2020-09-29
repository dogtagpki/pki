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

import com.netscape.certsrv.base.EBaseException;

/**
 * This class represents authentication exceptions.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class EAuthException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -2763649418082002427L;
    /**
     * Resource class name
     */
    private static final String AUTH_RESOURCES = "com.netscape.certsrv.authentication.AuthResources";

    /**
     * Constructs an authentication exception
     * <P>
     *
     * @param msgFormat exception details
     */
    public EAuthException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a auth exception with a exception parameter.
     * <P>
     *
     * @param msgFormat exception details in message string format
     * @param exception system exception
     */
    public EAuthException(String msgFormat, Exception exception) {
        super(msgFormat, exception);
    }

    /**
     * Constructs a auth exception with a list of parameters.
     * <P>
     *
     * @param msgFormat the message format.
     * @param params list of message format parameters
     */
    public EAuthException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Returns the resource bundle name
     *
     * @return resource bundle name.
     */
    protected String getBundleName() {
        return AUTH_RESOURCES;
    }

}
