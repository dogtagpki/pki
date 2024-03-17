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

import java.io.*;

public abstract class AbstractCommClient implements CommClient {
    boolean _finished = false;
    String _username;
    String _password;

    public AbstractCommClient(String username, String password) {
        _username = username;
        _password = password;
    }

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
    public void errorHandler(Exception exception, CommRecord cr) {
        System.err.println("errorHandler: " + exception);
        finish();
    }

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
    public String username(Object authObject, CommRecord cr) {
        return _username;
    }


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
    public String password(Object authObject, CommRecord cr) {
        return _password;
    }

    public synchronized void waitForFinish() {
        while (!_finished) {
            try {
                wait();
            } catch (Exception e) {
                System.err.println("waitForFinish errorHandler: " + e);
            }
        }
    }

    public synchronized void finish() {
        _finished = true;
        notifyAll();
    }
}
