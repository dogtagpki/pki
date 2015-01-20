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
package com.netscape.certsrv.base;

import java.util.Locale;

/**
 * An exception with localizable error messages. It is the
 * base class for all exceptions in certificate server.
 * <P>
 *
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 * @see com.netscape.certsrv.base.BaseResources
 */
public class EBaseException extends Exception {

    /**
     *
     */
    private static final long serialVersionUID = 8213021692117483973L;

    /**
     * The resource bundle to use for error messages.
     * Subclasses can override to use its own resource bundle.
     */
    private static final String BASE_RESOURCES = BaseResources.class.getName();

    /**
     * Parameters to the exception error message.
     */
    public Object mParams[] = null;

    /**
     * Constructs an instance of this exception with the given resource key.
     * If resource key is not found in the resource bundle, the resource key
     * specified is used as the error message.
     *
     * <pre>
     * new EBaseException(BaseResources.PERMISSION_DENIED);
     * new EBaseException(&quot;An plain error message&quot;);
     * <P>
     * @param msgFormat The error message resource key.
     */
    public EBaseException(String msgFormat) {
        super(msgFormat);
        mParams = null;
    }

    /**
     * Constructs an instance of this exception given the resource key and
     * the cause exception.
     *
     * <pre>
     *     try {
     *         ...
     *     } catch (IOExeption e) {
     *         throw new EBaseException(BaseResources.INTERNAL_ERROR_1, e);
     *     }
     * </pre>
     *
     * @param msgFormat The resource key
     * @param cause The cause exception
     */
    public EBaseException(String msgFormat, Exception cause) {
        super(msgFormat, cause);
        mParams = new Exception[1];
        mParams[0] = cause;
    }

    /**
     * Constructs an instance of this exception given the resource key and
     * an array of parameters.
     * <P>
     *
     * @param msgFormat The resource key
     * @param params Array of params
     */
    public EBaseException(String msgFormat, Object params[]) {
        super(msgFormat);
        mParams = params;
    }

    /**
     * Constructs an instance of this exception given the resource key,
     * an array of parameters, and the cause exception.
     * <P>
     *
     * @param msgFormat The resource key
     * @param params Array of params
     * @param cause The cause exception
     */
    public EBaseException(String msgFormat, Object params[], Exception cause) {
        super(msgFormat, cause);
        mParams = params;
    }

    /**
     * Constructs an instance of this exception given the cause exception.
     *
     * <pre>
     *     try {
     *         ...
     *     } catch (IOExeption e) {
     *         throw new EBaseException(e);
     *     }
     * </pre>
     *
     * @param cause The cause exception
     */
    public EBaseException(Exception cause) {
        super(cause.getMessage() == null ? cause.getClass().getName() : cause.getMessage(), cause);
        mParams = new Exception[1];
        mParams[0] = cause;
    }

    /**
     * Returns the list of parameters.
     * <P>
     *
     * @return List of parameters.
     */
    public Object[] getParameters() {
        return mParams;
    }

    /**
     * Returns the exception string in the default locale.
     * <P>
     *
     * @return The exception string in the default locale.
     */
    public String toString() {
        return toString(Locale.getDefault());
    }

    /**
     * Returns the exception string in the given locale.
     * <P>
     *
     * @param locale The locale
     * @return The exception string in the given locale.
     */
    public String toString(Locale locale) {
        return MessageFormatter.getLocalizedString(locale, getBundleName(),
                super.getMessage(), mParams);
    }

    /**
     * Returns the given resource bundle name.
     *
     * @return the name of the resource bundle for this class.
     */
    protected String getBundleName() {
        return BASE_RESOURCES;
    }

}
