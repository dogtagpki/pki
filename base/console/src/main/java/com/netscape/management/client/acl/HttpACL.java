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
package com.netscape.management.client.acl;

import java.io.Writer;
import java.io.Reader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.URL;

import com.netscape.management.client.comm.CommClient;
import com.netscape.management.client.comm.CommRecord;
import com.netscape.management.client.comm.HttpManager;

/**
 * HttpACL extends the ACL class to manipulate web server
 * resident ONE ACLs, accessed via CGI.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 8/19/97
 * @see ACL
 */
public class HttpACL extends FileACL implements CommClient {
    protected boolean ready;
    protected Reader reader;

    protected Reader openACLReader(Object ACLref) throws IOException {
        // The HttpACL subclass expects the ACLref
        // parameter to be a URL object, representing
        // the ACL source.

        open((URL) ACLref);
        return (reader);
    }

    protected synchronized void open(URL url)
        throws IOException {
        ready = false;

        HttpManager h = new HttpManager();

        h.get(url, this, null);

        while (!ready) {
            try {
                wait();
            } catch (Exception e) { }
        }
    }

    public synchronized void finish() {
        ready = true;
        notifyAll();
    }

    protected Writer openACLWriter(Object ACLref) throws IOException {
        // The HttpACL subclass expects the ACLref
        // parameter to be a URL object, representing
        // the ACL source.

        return (new HttpWriter(ACLref));
    }

    public void replyHandler(InputStream response, CommRecord cr) {
        reader = new InputStreamReader(response);
        finish();
    }

    public void errorHandler(Exception exception, CommRecord cr) {
        Exception e = (Exception) exception;

        System.err.println("errorHandler: " + e);
        finish();
    }

    public String username(Object realm, CommRecord cr) {
        return "";
    }

    public String password(Object realm, CommRecord cr) {
        return "";
    }
}
