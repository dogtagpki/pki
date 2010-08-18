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
package com.netscape.certsrv.acls;


import java.util.*;
import com.netscape.certsrv.base.*;


/**
 * A class represents an acls exception. Note that this is
 * an Runtime exception so that methods used AccessManager
 * do not have to explicity declare this exception. This
 * allows AccessManager to be easily integrated into any
 * existing code.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class EACLsException extends EBaseException {

    /**
     * resource class name
     */
    private static final String ACL_RESOURCES = ACLsResources.class.getName();
 
    /**
     * Constructs an acls exception.
     * <P>
     * @param msgFormat exception details
     */
    public EACLsException(String msgFormat) {
        super(msgFormat);
        mParams = null;
    }

    /**
     * Constructs a base exception with a parameter. For example,
     * <PRE>
     * 		new EACLsException("failed to load {0}", fileName);
     * </PRE>
     * <P>
     *
     * @param msgFormat exception details in message string format
     * @param param message string parameter
     */
    public EACLsException(String msgFormat, String param) {
        super(msgFormat);
        mParams = new String[1];
        mParams[0] = param;
    }

    /**
     * Constructs a base exception. It can be used to carry
     * a system exception that may contain information about
     * the context. For example,
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (IOExeption e) {
     * 		 	throw new EACLsException("Encountered System Error {0}", e);
     *      }
     * </PRE>
     * <P>
     *
     * @param msgFormat exception details in message string format
     * @param param system exception
     */
    public EACLsException(String msgFormat, Exception param) {
        super(msgFormat);
        mParams = new Exception[1];
        mParams[0] = param;
    }

    /**
     * Constructs a base exception with a list of parameters
     * that will be substituted into the message format.
     * <P>
     *
     * @param msgFormat exception details in message string format
     * @param params list of message format parameters
     */
    public EACLsException(String msgFormat, Object params[]) {
        super(msgFormat);
        mParams = params;
    }

    /**
     * Returns a list of parameters.
     * <P>
     *
     * @return list of message format parameters
     */
    public Object[] getParameters() {
        return mParams;
    }

    /**
     * String representation for the corresponding exception.
     * @return String representation for the corresponding exception.
     */
    public String toString() {
        return toString(Locale.getDefault());
    }

    /**
     * Returns string representation for the corresponding exception.
     * @param locale client specified locale for string representation.
     * @return String representation for the corresponding exception.
     */
    public String toString(Locale locale) {
        return MessageFormatter.getLocalizedString(locale, getBundleName(),
                super.getMessage(), mParams);
    }

    /**
     * Return the class name of the resource bundle.
     * @return class name of the resource bundle.
     */
    protected String getBundleName() {
        return ACL_RESOURCES;
    }
}
