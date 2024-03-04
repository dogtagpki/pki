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

import java.io.InputStream;

/**
 * The CommClient interface is implemented by any object that wishes
 * to receive asynchronous responses or errors from a communication
 * channel.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.4, 8/25/97
 * @see     CommChannel
 * @see     CommManager
 */
public abstract interface CommClient {
    /**
      * Will be called on receipt of a response from the communication
      * channel.
      *
      * @param replyStream an InputStream object for the response.
      *  Note that the InputStream is a byte-oriented input API; if
      *  you intend to read characters from the response stream, you
      *  should open an InputStreamReader object on the stream to
      *  read 16-bit unicode characters, to support internationalization.
      * @param cr the CommRecord object of the current communication
      *  transaction.
      * @see CommRecord
      */
    public abstract void replyHandler(InputStream replyStream,
            CommRecord cr);

    /**
     * Will be called on recognition of an error from the communication
     * channel.
     *
     * @param exception the error exception
     * @param cr the CommRecord object of the current communication
     *  transaction.
     * @see CommRecord
     */
    public abstract void errorHandler(Exception exception, CommRecord cr);

    /**
     * Will be called on recognition of an authentication request from
     * the communication channel.
     *
     * @param authObject a protocol-specific authentication argument.
     * @param cr the CommRecord object of the current communication
     *  transaction.
     * @return the username for authentication.
     * @see CommRecord
     */
    public abstract String username(Object authObject, CommRecord cr);

    /**
     * Will be called on recognition of an authentication request from
     * the communication channel.
     *
     * @param authObject a protocol-specific authentication argument.
     * @param cr the CommRecord object of the current communication
     *  transaction.
     * @return the password for authentication.
     * @see CommRecord
     */
    public abstract String password(Object authObject, CommRecord cr);
}
