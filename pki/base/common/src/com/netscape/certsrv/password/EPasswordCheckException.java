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
package com.netscape.certsrv.password;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PasswordResources;

/**
 * A class represents a password checker exception.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class EPasswordCheckException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = 6274695122717026554L;
    /**
     * Resource class name.
     */
    private static final String PASSWORD_CHECK_RESOURCES = PasswordResources.class.getName();

    /**
     * Constructs a password checker exception
     * <P>
     * @param msgFormat exception details
     */
    public EPasswordCheckException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a password checker exception.
     * <P>
     * @param msgFormat exception details in message string format
     * @param param message string parameter
     */
    public EPasswordCheckException(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a password checker exception.
     * <P>
     * @param msgFormat exception details in message string format
     * @param exception system exception
     */
    public EPasswordCheckException(String msgFormat, Exception exception) {
        super(msgFormat, exception);
    }

    /**
     * Constructs a password checker exception.
     * <P>
     * @param msgFormat the message format.
     * @param params list of message format parameters
     */
    public EPasswordCheckException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Retrieves bundle name.
     * @return resource bundle name.
     */
    protected String getBundleName() {
        return PASSWORD_CHECK_RESOURCES;
    }
}
