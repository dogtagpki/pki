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
package com.netscape.certsrv.kra;

import com.netscape.certsrv.base.EBaseException;

/**
 * A class represents a KRA exception. This is the base exception for all the
 * KRA specific exceptions. It is associated with <CODE>KRAResources</CODE>.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public class EKRAException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -6803576959258754821L;
    /**
     * KRA resource class name.
     * <P>
     */
    private static final String KRA_RESOURCES = KRAResources.class.getName();

    /**
     * Constructs a KRA exception.
     * <P>
     * 
     * @param msgFormat constant from KRAResources.
     */
    public EKRAException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a KRA exception.
     * <P>
     * 
     * @param msgFormat constant from KRAResources.
     * @param param additional parameters to the message.
     */
    public EKRAException(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a KRA exception.
     * <P>
     * 
     * @param msgFormat constant from KRAResources.
     * @param e embedded exception.
     */
    public EKRAException(String msgFormat, Exception e) {
        super(msgFormat, e);
    }

    /**
     * Constructs a KRA exception.
     * <P>
     * 
     * @param msgFormat constant from KRAResources.
     * @param params additional parameters to the message.
     */
    public EKRAException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Returns the bundle file name.
     * <P>
     * 
     * @return name of bundle class associated with this exception.
     */
    protected String getBundleName() {
        return KRA_RESOURCES;
    }
}
