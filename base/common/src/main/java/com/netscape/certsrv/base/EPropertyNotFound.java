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
package com.netscape.certsrv.base;

/**
 * This class represents an exception thrown when a
 * property is not found in the configuration store.
 * It extends EBaseException and uses the same resource bundle.
 * <p>
 *
 * @version $Revision$, $Date$
 * @see com.netscape.certsrv.base.EBaseException
 */
public class EPropertyNotFound extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = 2701966082697733003L;

    /**
     * Constructs an instance of this exception given the name of the
     * property that's not found.
     * <p>
     *
     * @param errorString Detailed error message.
     */
    public EPropertyNotFound(String errorString) {
        super(errorString);
    }
}
