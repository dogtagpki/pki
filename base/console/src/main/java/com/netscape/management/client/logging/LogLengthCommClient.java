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
package com.netscape.management.client.logging;

import java.io.*;
import java.util.*;
import com.netscape.management.client.comm.*;


/**
 * A CommClient class (HTTP client)
 */
public class LogLengthCommClient extends AbstractCommClient {
    /**
      * constructor
      */
    public LogLengthCommClient(String username, String password) {
        super(username, password);
    }

    /**
      * Will be called on receipt of a response from the communication
      * channel.
      */
    public void replyHandler(InputStream replyStream, CommRecord cr) {
        BufferedReader replyBuffer =
                new BufferedReader(new InputStreamReader(replyStream));
        try {
            String logEntry;
            while ((logEntry = replyBuffer.readLine()) != null) {
                StringTokenizer st = new StringTokenizer(logEntry, "=");
                if (st.hasMoreTokens()) {
                    if (st.nextToken().equals("count")) {
                        String rowCount = st.nextToken();
                        StringBuffer logLength = (StringBuffer) cr.getArg();
                        logLength.append(rowCount);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println(e);
        }
        finish();
    }
}
