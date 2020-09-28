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

import java.lang.reflect.Method;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Factors out common function of formatting internatinalized
 * messages taking arguments and using java.util.ResourceBundle
 * and java.text.MessageFormat mechanism.
 * <P>
 *
 * @version $Revision$, $Date$
 * @see java.text.MessageFormat
 * @see java.util.ResourceBundle
 */
public class MessageFormatter {

    private static final Class<?>[] toStringSignature = { Locale.class };

    /**
     * Retrieves the localized string.
     *
     * @param locale end user locale
     * @param resourceBundleBaseName resource bundle class name
     * @param formatString format string
     * @return localized string
     */
    public static String getLocalizedString(
            Locale locale, String resourceBundleBaseName,
            String formatString) {
        return getLocalizedString(locale, resourceBundleBaseName,
                formatString, null);
    }

    /**
     * Retrieves the localized string.
     *
     * @param locale end user locale
     * @param resourceBundleBaseName resource bundle class name
     * @param formatString format string
     * @param params parameters to be substituted
     * @return localized string
     */
    public static String getLocalizedString(
            Locale locale, String resourceBundleBaseName,
            String formatString, Object params) {
        Object o[] = new Object[1];

        o[0] = params;
        return getLocalizedString(locale, resourceBundleBaseName,
                formatString, o);
    }

    /**
     * Retrieves the localized string.
     *
     * @param locale end user locale
     * @param resourceBundleBaseName resource bundle class name
     * @param formatString format string
     * @param params parameters to be substituted
     * @return localized string
     */
    public static String getLocalizedString(
            Locale locale, String resourceBundleBaseName,
            String formatString, Object[] params) {

        String localizedFormat = null;

        try {
            // if you are worried about the efficiency of the
            // following line, dont worry. ResourceBundle has
            // an internal cache. So resource bundle wont be
            // instantiated everytime you call toString().

            localizedFormat = ResourceBundle.getBundle(
                    resourceBundleBaseName, locale).getString(formatString);
        } catch (MissingResourceException e) {
            return formatString;

        }
        Object[] localizedParams = params;
        Object[] localeArg = null;

        if (params != null) {
            for (int i = 0; i < params.length; ++i) {
                if (!(params[i] instanceof String) ||
                        !(params[i] instanceof Date) ||
                        !(params[i] instanceof Number)) {
                    if (localizedParams == params) {

                        // only done once
                        // NB if the following variant of cloning code is used
                        //         localizedParams = (Object [])mParams.clone();
                        // it causes ArrayStoreException in
                        //         localizedParams[i] = params[i].toString();
                        // below

                        localizedParams = new Object[params.length];
                        System.arraycopy(params, 0, localizedParams, 0,
                                params.length);
                    }
                    try {
                        Method toStringMethod = params[i].getClass().getMethod(
                                "toString", toStringSignature);

                        if (localeArg == null) {
                            // only done once
                            localeArg = new Object[] { locale };
                        }
                        localizedParams[i] = toStringMethod.invoke(
                                params[i], localeArg);
                    } catch (Exception e) {
                        // no method for localization, fall back
                        localizedParams[i] = params[i].toString();
                    }
                }
            }
        }
        try {
            // XXX - runtime exception may be raised by the following function
            MessageFormat format = new MessageFormat(localizedFormat);

            return format.format(localizedParams);
        } catch (IllegalArgumentException e) {
            // XXX - for now, we just print the unformatted message
            // if the exception is raised
            return localizedFormat;
        }
    }
}
