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
package com.netscape.cmscore.util;

import java.util.Locale;

import com.netscape.certsrv.base.MessageFormatter;

/**
 * This object is used to easily create I18N messages for utility
 * classes and standalone programs.
 *
 * @author mikep
 * @version $Revision$, $Date$
 * @see com.netscape.certsrv.base.MessageFormatter
 * @see com.netscape.cmscore.util.UtilResources
 */
public class UtilMessage {

    protected Object mParams[] = null;

    private String mMessage = null;

    /**
     * The bundle name for this event.
     */
    static String mBundleName = UtilResources.class.getName();

    /**
     * Constructs a message event
     * <P>
     *
     * @param msgFormat the message string
     */
    public UtilMessage(String msgFormat) {
        mMessage = msgFormat;
        mParams = null;
    }

    /**
     * Constructs a message with a parameter. For example,
     *
     * <PRE>
     * new UtilMessage(&quot;failed to load {0}&quot;, fileName);
     * </PRE>
     * <P>
     *
     * @param msgFormat details in message string format
     * @param param message string parameter
     */
    public UtilMessage(String msgFormat, String param) {
        this(msgFormat);
        mParams = new String[1];
        mParams[0] = param;
    }

    /**
     * Constructs a message from an exception. It can be used to carry
     * a system exception that may contain information about
     * the context. For example,
     *
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (IOExeption e) {
     * 		 	out.println(new UtilMessage("Encountered System Error {0}", e);
     *      }
     * </PRE>
     * <P>
     *
     * @param msgFormat exception details in message string format
     * @param exception system exception
     */
    public UtilMessage(String msgFormat, Exception exception) {
        this(msgFormat);
        mParams = new Exception[1];
        mParams[0] = exception;
    }

    /**
     * Constructs a message from a base exception. This will use the msgFormat
     * from the exception itself.
     *
     * <PRE>
     * 		try {
     *  		...
     * 		} catch (Exception e) {
     * 		 	System.out.println(new UtilMessage(e));
     *      }
     * </PRE>
     * <P>
     *
     * @param exception CMS exception
     */
    public UtilMessage(Exception e) {
        this(e.getMessage());
        mParams = new Exception[1];
        mParams[0] = e;
    }

    /**
     * Constructs a message event with a list of parameters
     * that will be substituted into the message format.
     * <P>
     *
     * @param msgFormat message string format
     * @param params list of message format parameters
     */
    public UtilMessage(String msgFormat, Object params[]) {
        this(msgFormat);
        mParams = params;
    }

    /**
     * Returns the current message format string.
     * <P>
     *
     * @return details message
     */
    public String getMessage() {
        return mMessage;
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
     * Returns localized message string. This method should
     * only be called if a localized string is necessary.
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
                getMessage(),
                getParameters());
    }

    /**
     * Gets the resource bundle name for this class instance. This should
     * be overridden by subclasses who have their own resource bundles.
     */
    protected String getBundleName() {
        return mBundleName;
    }

}
