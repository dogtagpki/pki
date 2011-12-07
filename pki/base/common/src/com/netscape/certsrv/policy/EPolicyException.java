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
package com.netscape.certsrv.policy;

import java.util.Locale;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MessageFormatter;

/**
 * This class represents Exceptions used by the policy package. The policies
 * themselves do not raise exceptions but use them to format error messages.
 * 
 * Adapted from EBasException
 * <P>
 * 
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 * 
 * @deprecated
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 */
public class EPolicyException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -1969940775036388085L;
    /**
     * Resource class name.
     */
    private static final String POLICY_RESOURCES = PolicyResources.class
            .getName();

    /**
     * Constructs a base exception.
     * <P>
     * 
     * @param msgFormat exception details
     */
    public EPolicyException(String msgFormat) {
        super(msgFormat);
        mParams = null;
    }

    /**
     * Constructs a base exception with a parameter. For example,
     * 
     * <PRE>
     * new EPolicyException(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     * 
     * @param msgFormat exception details in message string format
     * @param param message string parameter
     */
    public EPolicyException(String msgFormat, String param) {
        super(msgFormat);
        mParams = new String[1];
        mParams[0] = param;
    }

    /**
     * Constructs a base exception with two String parameters. For example,
     * <P>
     * 
     * @param msgFormat exception details in message string format
     * @param param1 message string parameter
     * @param param2 message string parameter
     */
    public EPolicyException(String msgFormat, String param1, String param2) {
        super(msgFormat);
        mParams = new String[2];
        mParams[0] = param1;
        mParams[1] = param2;
    }

    /**
     * Constructs a base exception. It can be used to carry a system exception
     * that may contain information about the context. For example,
     * 
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (IOExeption e) {
     * 		 	throw new EPolicyException("Encountered System Error {0}", e);
     *      }
     * </PRE>
     * <P>
     * 
     * @param msgFormat exception details in message string format
     * @param param system exception
     */
    public EPolicyException(String msgFormat, Exception param) {
        super(msgFormat);
        mParams = new Exception[1];
        mParams[0] = param;
    }

    /**
     * Constructs a base exception with a list of parameters that will be
     * substituted into the message format.
     * <P>
     * 
     * @param msgFormat exception details in message string format
     * @param params list of message format parameters
     */
    public EPolicyException(String msgFormat, Object params[]) {
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
     * Returns localized exception string. This method should only be called if
     * a localized string is necessary.
     * <P>
     * 
     * @return details message
     */
    public String toString() {
        return toString(Locale.getDefault());
    }

    /**
     * Returns the string based on the given locale.
     * <P>
     * 
     * @param locale locale
     * @return details message
     */
    public String toString(Locale locale) {
        return MessageFormatter.getLocalizedString(locale, getBundleName(),
                super.getMessage(), mParams);
    }

    protected String getBundleName() {
        return POLICY_RESOURCES;
    }

}
