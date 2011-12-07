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
package com.netscape.certsrv.notification;

import com.netscape.certsrv.base.EBaseException;

/**
 * A class represents a notification exception.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public class ENotificationException extends EBaseException {

    /**
     *
     */
    private static final long serialVersionUID = 2101529206306996303L;
    /**
     * Identity resource class name.
     */
    private static final String NOTIFICATION_RESOURCES = NotificationResources.class
            .getName();

    /**
     * Constructs a notification exception
     * <P>
     */
    public ENotificationException(String msgFormat) {
        super(msgFormat);
    }

    /**
     * Constructs a Identity exception.
     * <P>
     */
    public ENotificationException(String msgFormat, String param) {
        super(msgFormat, param);
    }

    /**
     * Constructs a Identity exception.
     * <P>
     */
    public ENotificationException(String msgFormat, Exception e) {
        super(msgFormat, e);
    }

    /**
     * Constructs a Identity exception.
     * <P>
     */
    public ENotificationException(String msgFormat, Object params[]) {
        super(msgFormat, params);
    }

    /**
     * Retrieves bundle name.
     */
    protected String getBundleName() {
        return NOTIFICATION_RESOURCES;
    }
}
