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
package com.netscape.certsrv.dbs;


import java.util.*;
import com.netscape.certsrv.base.*;


/**
 * A class represents a database exception.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class EDBException extends EBaseException {

    /**
     * Resource class name.
     */
    private static final String DB_RESOURCES = DBResources.class.getName();		

    /**
     * Constructs a database exception.
     * <P>
     *
     * @param msgFormat message format
     */
    public EDBException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a database exception.
     * <P>
     *
     * @param msgFormat message format
     * @param param parameter
     */
    public EDBException(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a database exception.
     * <P>
     *
     * @param msgFormat message format
     * @param e exception as parameter
     */
    public EDBException(String msgFormat, Exception e) {
        super(msgFormat, e);
    }

    /**
     * Constructs a database exception.
     * <P>
     *
     * @param msgFormat message format
     * @param params list of parameters
     */
    public EDBException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    protected String getBundleName() {
        return DB_RESOURCES;
    }
}
