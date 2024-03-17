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

/**
 * Extends CommClient to add support for progress reporting
 * @see     CommClient
 * @see     IProgressListener
 */
public abstract interface CommClient2 extends CommClient {
    /**
      * Will be called when a block of data has been read from the communication
      * channel. Compatible with util.IProgressListener
      *
      * @param targetName the document being transfered
      * @param total the total size of the document in bytes
      * @param done the number of transferred bytes
      * @see IProgressListener
      */
    public abstract void progressUpdate(String targetName, int total,
            int done);

}
