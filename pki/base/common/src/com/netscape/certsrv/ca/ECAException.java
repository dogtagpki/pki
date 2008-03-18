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


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.logging.*;


/**
 * A class represents a CA exception.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ECAException extends EBaseException {

    /**
     * CA resource class name.
     */
    private static final String CA_RESOURCES = CAResources.class.getName();		

    /**
     * Constructs a CA exception.
     * <P>
     * @param msgFormat constant from CAResources.
     */
    public ECAException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a CA exception.
     * <P>
     * @param msgFormat constant from CAResources.
     * @param param additional parameters to the message.
     */
    public ECAException(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a CA exception.
     * <P>
     * @param msgFormat constant from CAResources.
     * @param e embedded exception.
     */
    public ECAException(String msgFormat, Exception e) {
        super(msgFormat, e);
    }

    /**
     * Constructs a CA exception.
     * <P>
     * @param msgFormat constant from CAResources.
     * @param params additional parameters to the message.
     */
    public ECAException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Returns the bundle file name.
     * <P>
     * @return name of bundle class associated with this exception.
     */
    protected String getBundleName() {
        return CA_RESOURCES;
    }
}
