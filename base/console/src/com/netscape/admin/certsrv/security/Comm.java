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
package com.netscape.admin.certsrv.security;

import java.io.*;
import java.net.*;
import java.util.*;

import com.netscape.management.client.comm.*;
import com.netscape.management.client.util.*;

/**
 *
 * Extends dt's comm package to do some communication with backend.
 * eventually this will be phase out, and key cert related tasks that
 * require cgi call will use AdmTask.java instead of this one.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
class Comm implements CommClient, Runnable {
    public static final int DEFAULT_TIMEOUT_PERIOD = 30000; // 30 seconds
    public boolean finished = false;
    public String value = null;


    static String server_response = null;

    String url_cgi;
    Hashtable cgi_arg;
    boolean waitForResponse;

    String id = "Admin";
    String pw = "Admin";

    Exception error = null;

    public Comm(String url_cgi, Hashtable cgi_arg,
            boolean waitForResponse) {
        this.url_cgi = url_cgi;
        this.cgi_arg = cgi_arg;
        this.waitForResponse = waitForResponse;
    }


    public void setAuth(String userName, String password) {
        this.id = userName;
        this.pw = password;
    }

    public Exception getError() {
        return error;
    }

    public static String getData() {
        return server_response;
    }

    public void run() {
        HttpManager h = new HttpManager();

        try {
            ByteArrayInputStream value = HttpChannel.encode(cgi_arg);
            h.post(new URL(url_cgi), this, null, value,
                    value == null ? 0 : value.available(),
                    CommManager.FORCE_BASIC_AUTH);
            awaitValue();
        } catch (InterruptedIOException timeout) {
            error = timeout;
        }
        catch (ConnectException connectError) {
            error = connectError;
        }
        catch (IOException ioError) {
            error = ioError;
        }
        catch (Exception e) {
            error = e;
        }
    }

    public synchronized void awaitValue() {
        try {
            wait(DEFAULT_TIMEOUT_PERIOD);
        } catch (Exception e) {
            error = e;
        }
        if (value == null) {
            error = new InterruptedIOException("HTTP response timeout");
        }
    }


    public synchronized void finish() {
        finished = true;
        notifyAll();
    }

    public synchronized void setValue(String s) {
        value = s;

        server_response = s;

        notifyAll();
    }

    public void replyHandler(InputStream response, CommRecord cr) {
        try {
            InputStreamReader reader =
                    new InputStreamReader(response, "UTF8");
            int c = reader.read();

            if (c == 'S') {
                finish();
                return;
            }
            String s = (char) c + "";

            while ((c = reader.read()) != -1) {
                s += (char) c + "";
            }

            setValue(s);
        } catch (Exception e) {
            error = e;
        }
    }

    public void errorHandler(Exception exception, CommRecord cr) {
        error = exception;
        Debug.println("errorHandler: " + exception);
        finish();
    }

    public String username(Object auth, CommRecord cr) {
        return id;
    }

    public String password(Object auth, CommRecord cr) {
        return pw;
    }
}
