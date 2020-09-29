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
package com.netscape.certsrv.listeners;

import com.netscape.certsrv.base.EBaseException;

/**
 * A class represents a listener exception.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class EListenersException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = 8895858413292894796L;
    /**
     * CA resource class name.
     */
    private static final String LISTENERS_RESOURCES = ListenersResources.class.getName();

    /**
     * Constructs a listeners exception.
     * <P>
     *
     * @param msgFormat The error message resource key.
     */
    public EListenersException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a Listeners exception.
     * <P>
     *
     * @param msgFormat The resource key.
     * @param e The parameter as an exception.
     */
    public EListenersException(String msgFormat, Exception e) {
        super(msgFormat, e);
    }

    /**
     * Constructs a Listeners exception.
     * <P>
     *
     * @param msgFormat The resource key.
     * @param params Array of params.
     */
    public EListenersException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * get the listener resource class name.
     * <P>
     *
     * @return the class name of the resource.
     */
    protected String getBundleName() {
        return LISTENERS_RESOURCES;
    }
}
