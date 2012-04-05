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
package com.netscape.admin.certsrv;

import java.io.*;
import java.util.*;

/**
 * A class represents an administartive exception. By
 * using this exception, the locale conversion can be
 * delayed until it is necessary. THIS CLASS DOES NOT
 * SUPPORT MESSAGE FORMAT.
 * <P>
 *
 * @author jpanchen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv
 */
public class EAdminException extends Exception {

    /*==========================================================
     * variables
     *==========================================================*/
	public static final String RESOURCES = CMSAdminResources.class.getName();
	private boolean mIsLocalized = false;
	private ResourceBundle mResource;

	/*==========================================================
     * constructors
     *==========================================================*/

	/**
	 * Constructs an exception.
	 * <P>
	 *
	 * @param msgFormat exception details
	 * @param isLocalized true if the string is localized already
	 */
	public EAdminException(String msgFormat, boolean isLocalized) {
		super(msgFormat);
		mResource = ResourceBundle.getBundle(RESOURCES);
		mIsLocalized = isLocalized;
	}

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Check if the original message is localized already
     *
     * @return true if the message is localized
     */
    public boolean isLocalized() {
        return mIsLocalized;
    }

	/**
	 * Returns localized exception string. This method should
	 * only be called if a localized string is necessary.
	 * <P>
	 *
	 * @return details message
	 */
	public String toString() {
		return getMessage();
	}

	/**
	 * Returns the string based on the given locale.
	 * This is costly since resource boundle is created each time. Use
	 * this only when it is necessary.
	 *
	 * @param locale locale
	 * @return details message
	 */
	public String toString(Locale locale) {
        ResourceBundle resource = ResourceBundle.getBundle(RESOURCES, locale);
        try {
            return resource.getString(super.getMessage());
        } catch (MissingResourceException e) {
            return super.getMessage()+"-"+e.toString();
        } catch (Exception ex) {
            return super.getMessage();
        }
	}

	/**
	 * Returns the message based on the given locale.If the original message
	 * is mark localized, the orginal message will be returned without
	 * converstion. This is costly since resource boundle is created each time.Use
	 * this only when it is necessary.<P>
	 *
	 * @param locale user specify local
	 * @return string representation in specified local
	 */
    public String getMessage(Locale locale){
        return toString(locale);
    }

    /**
	 * Returns the message in default locale. If the original message
	 * is mark localized, the orginal message will be returned without
	 * converstion.<P>
	 *
	 * @return localized detial exception string
	 */
    public String getMessage(){
        if (mIsLocalized)
            return super.getMessage();
        try {
            return mResource.getString(super.getMessage());
        } catch (MissingResourceException e) {
            return super.getMessage()+"-"+e.toString();
        } catch (Exception ex) {
            return super.getMessage();
        }
    }

    /**
     * Returns the message or message tag unconvrted
     */
    public String getMessageString() {
        return super.getMessage();
    }

}
