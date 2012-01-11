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
package com.netscape.certsrv.logging;

import java.util.Locale;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MessageFormatter;

/**
 * This class implements a Log exception. LogExceptions
 * should be caught by LogSubsystem managers.
 * <P>
 * 
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 */
public class ELogException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = -8903703675126348145L;
    /**
     * Resource bundle class name.
     */
    private static final String LOG_RESOURCES = LogResources.class.getName();

    /**
     * Constructs a log exception.
     * <P>
     * 
     * @param msgFormat Exception details.
     */
    public ELogException(String msgFormat) {
        super(msgFormat);
        mParams = null;
    }

    /**
     * Constructs a log exception with a parameter. For example,
     * 
     * <PRE>
     * new ELogException(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     * 
     * @param msgFormat Exception details in message string format.
     * @param param Message string parameter.
     */
    public ELogException(String msgFormat, String param) {
        super(msgFormat);
        mParams = new String[1];
        mParams[0] = param;
    }

    /**
     * Constructs a log exception. It can be used to carry
     * a system exception that may contain information about
     * the context. For example,
     * 
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (IOExeption e) {
     * 		 	throw new ELogException("Encountered System Error {0}", e);
     *      }
     * </PRE>
     * <P>
     * 
     * @param msgFormat Exception details in message string format.
     * @param param System exception.
     */
    public ELogException(String msgFormat, Exception param) {
        super(msgFormat);
        mParams = new Exception[1];
        mParams[0] = param;
    }

    /**
     * Constructs a log exception with a list of parameters
     * that will be substituted into the message format.
     * <P>
     * 
     * @param msgFormat Exception details in message string format.
     * @param params List of message format parameters.
     */
    public ELogException(String msgFormat, Object params[]) {
        super(msgFormat);
        mParams = params;
    }

    /**
     * Returns a list of parameters.
     * <P>
     * 
     * @return list of message format parameters.
     */
    public Object[] getParameters() {
        return mParams;
    }

    /**
     * Returns localized exception string. This method should
     * only be called if a localized string is necessary.
     * <P>
     * 
     * @return Details message.
     */
    public String toString() {
        return toString(Locale.getDefault());
    }

    /**
     * Returns the string based on the given locale.
     * <P>
     * 
     * @param locale Locale.
     * @return Details message.
     */
    public String toString(Locale locale) {
        return MessageFormatter.getLocalizedString(locale, getBundleName(),
                super.getMessage(), mParams);
    }

    /**
     * Retrieves resource bundle name.
     * Subclasses should override this as necessary
     * 
     * @return String containing name of resource bundle.
     */

    protected String getBundleName() {
        return LOG_RESOURCES;
    }

}
