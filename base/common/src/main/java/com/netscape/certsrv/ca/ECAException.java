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
package com.netscape.certsrv.ca;

import com.netscape.certsrv.base.EBaseException;

/**
 * A class represents a CA exception.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class ECAException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -2963412888833532478L;
    /**
     * CA resource class name.
     */
    private static final String CA_RESOURCES = CAResources.class.getName();

    /**
     * Constructs a CA exception.
     * <P>
     *
     * @param msgFormat constant from CAResources.
     */
    public ECAException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a CA exception.
     * <P>
     *
     * @param msgFormat constant from CAResources.
     * @param cause cause of this exception.
     */
    public ECAException(String msgFormat, Throwable cause) {
        super(msgFormat, cause);
    }

    /**
     * Constructs a CA exception.
     * <P>
     *
     * @param msgFormat constant from CAResources.
     * @param params additional parameters to the message.
     */
    public ECAException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Returns the bundle file name.
     * <P>
     *
     * @return name of bundle class associated with this exception.
     */
    protected String getBundleName() {
        return CA_RESOURCES;
    }
}
