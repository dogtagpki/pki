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

import com.netscape.certsrv.base.EBaseException;

/**
 * This class represents authorization exceptions.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public class EAuthzException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = 6265731237976616272L;
    /**
     * Resource class name.
     */
    private static final String AUTHZ_RESOURCES = AuthzResources.class
            .getName();

    /**
     * Constructs a authz exception
     * <P>
     * 
     * @param msgFormat exception details
     */
    public EAuthzException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a authz exception with a parameter.
     * <p>
     * 
     * @param msgFormat exception details in message string format
     * @param param message string parameter
     */
    public EAuthzException(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a authz exception with a exception parameter.
     * <P>
     * 
     * @param msgFormat exception details in message string format
     * @param param system exception
     */
    public EAuthzException(String msgFormat, Exception param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a authz exception with a list of parameters.
     * <P>
     * 
     * @param msgFormat the message format.
     * @param params list of message format parameters
     */
    public EAuthzException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Returns the resource bundle name
     * 
     * @return resource bundle name
     */
    protected String getBundleName() {
        return AUTHZ_RESOURCES;
    }

}
