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
package com.netscape.management.client.comm;

import java.io.IOException;
import com.netscape.management.client.preferences.Preferences;

/**
 * The CommChannel interface is implemented by any object
 * that is to be managed by the CommManager. The object is
 * typically an encapsulated communication channel with
 * protocol support facilities.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 6/12/97
 * @see     CommManager
 */
public interface CommChannel {
    /**
      * Opens a communication channel. The channel should be connected
      * and available upon completion.
      *
      * @exception IOException if an I/O error occurs.
      */
    public void open() throws IOException;

    public void open(Preferences pref) throws IOException;

    /**
     * Closes a communication channel. The channel should be closed
     * and its resources released upon completion.
     *
     * @exception IOException if an I/O error occurs.
     */
    public void close() throws IOException;

    /**
     * Returns true if the communication channel is ready and available
     * for use.
     *
     */
    public boolean ready();

    /**
     * Returns the internal representation of the connection target,
     * specific to the communications channel class.
     *
     */
    public Object targetID();
}
