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
package com.netscape.admin.certsrv.connection;

import java.net.*;
import java.io.*;

/**
 * SSLConnectionFactory - factory method for creating supported SSL
 * Connection type: SSLAVA_CONNECTION, SSL_CONNECTION. DEFAULT connection
 * SSLAVA_CONNECTION will be used if type specified is incorrect.
 *
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.certsrv.client.connection
 */
public class SSLConnectionFactory implements IConnectionFactory {

    /*==========================================================
     * variables
     *==========================================================*/
    public static final String JSS_CONNECTION = "JSS";
    public static final String SSL_CONNECTION = "SSL";

    private String mType;

	/*==========================================================
     * constructors
     *==========================================================*/

     /**
      * Construct a specific SSL connection factory object
      *
      * DEFAULT connection SSLAVA_CONNECTION will be used if
      * type specified is incorrect.
      *
      * @param type supported SSL connection type:
      *        SSLAVA_CONNECTION, SSL_CONNECTION
      */
     public SSLConnectionFactory(String type) {
        if ((!type.equals(JSS_CONNECTION))&&(!type.equals(SSL_CONNECTION)) ) {
            System.out.println("SSL Connection Type not found default is used");
            mType = JSS_CONNECTION;
        } else {
            mType = type;
        }
     }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Creates connection using the host and port
     */
    public IConnection create(String host, int port)
        throws IOException, UnknownHostException {

        if (mType.equals(JSS_CONNECTION))
            return new JSSConnection(host, port);
        return new JSSConnection(host, port);    
        //return new SSLConnection(host, port);
    }

}
