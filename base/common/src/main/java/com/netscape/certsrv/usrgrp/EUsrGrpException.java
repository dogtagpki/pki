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
package com.netscape.certsrv.usrgrp;

import com.netscape.certsrv.base.EBaseException;

/**
 * A class represents a Identity exception.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class EUsrGrpException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = 5549165292376270875L;
    /**
     * Identity resource class name.
     */
    private static final String USRGRP_RESOURCES = "com.netscape.certsrv.usrgrp.UsrGrpResources";

    /**
     * Constructs a usr/grp management exception
     *
     * @param msgFormat exception details in message string format
     *            <P>
     */
    public EUsrGrpException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a Identity exception.
     *
     * @param e system exception
     *            <P>
     */
    public EUsrGrpException(String msgFormat, Exception e) {
        super(msgFormat, e);
    }

    /**
     * Constructs a Identity exception.
     *
     * @param msgFormat exception details in message string format
     * @param params list of message format parameters
     *            <P>
     */
    public EUsrGrpException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Retrieves bundle name.
     */
    protected String getBundleName() {
        return USRGRP_RESOURCES;
    }
}
