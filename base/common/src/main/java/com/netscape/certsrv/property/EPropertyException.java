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
package com.netscape.certsrv.property;

import com.netscape.certsrv.base.EBaseException;

/**
 * This is the base exception for property handling.
 *
 * @version $Revision$, $Date$
 */
public class EPropertyException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -6100285768016343010L;

    /**
     * Constructs property exception
     *
     * @param msg exception message
     */
    public EPropertyException(String msg) {
        super(msg);
    }

    public EPropertyException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public EPropertyException(Throwable cause) {
        super(cause.getMessage(), cause);
    }
}
