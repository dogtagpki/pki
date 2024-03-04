/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.acleditor;

/**
 * The CallbackAction class provides a simple callback
 * interface which can be used to pass callback methods
 * to other classes, as a means of providing a notification
 * service. CallbackAction objects can be chained by passing
 * one to the constructor of another.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 9/3/97
 */

public abstract class CallbackAction {
    public CallbackAction next = null;

    public CallbackAction() { };

    public CallbackAction(CallbackAction n) {
        next = n;
    };

    /**
     * Call this function to kickoff the callback chain.
     *
     * @param arg an Object argument.
     */
    public void go(Object arg) {
        callback(arg);

        if (next != null)
            next.callback(arg);
    }

    public abstract void callback(Object arg);
}
