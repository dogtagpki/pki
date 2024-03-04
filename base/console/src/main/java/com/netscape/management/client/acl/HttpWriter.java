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

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.IOException;
import java.net.URL;

import com.netscape.management.client.comm.CommClient;
import com.netscape.management.client.comm.CommRecord;
import com.netscape.management.client.comm.HttpManager;

/**
 * The HttpWriter class overides the close() method of the
 * CharArrayWriter class to implement a HTTP post on close.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2, 8/19/97
 * @see Task
 */
public class HttpWriter extends StringWriter implements CommClient {
    URL url;
    boolean finished;

    public HttpWriter(Object _url) {
        super();
        url = (URL)_url;
    }

    public void close() throws IOException {
        super.close();

        // force the post

        HttpManager h = new HttpManager();

        finished = false;

        String s = this.toString();

        try {
            h.post(url, this, null,
                    new ByteArrayInputStream(s.getBytes()), s.length());
        } catch (IOException ioe) {
            System.err.println("HttpWriter:close():" + ioe);
        }

        await();
    }

    protected synchronized void await() {
        while (!finished) {
            try {
                wait();
            } catch (Exception e) { }
        }
    }

    public synchronized void finish() {
        finished = true;
        notifyAll();
    }

    public void replyHandler(InputStream response, CommRecord cr) {
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
