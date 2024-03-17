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

import java.net.URL;
import java.net.MalformedURLException;
import java.io.IOException;
import java.io.InputStream;

import com.netscape.management.client.util.Debug;
import com.netscape.management.client.preferences.Preferences;

/**
 * This CommManager subclass implements connection management
 * for HTTP protocol CommChannels.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.3, 10/6/97
 * @see     CommManager
 */
public class HttpManager extends CommManager {
    final static public int HTTP_OK = 200;
    final static public int HTTP_CREATED = 201;
    final static public int HTTP_ACCEPTED = 202;
    final static public int HTTP_NOCONTENT = 204;
    final static public int HTTP_MOVEDTEMP = 301;
    final static public int HTTP_MOVEDPERM = 302;
    final static public int HTTP_ERROR = 400;
    final static public int HTTP_AUTHREQ = 401;
    final static public int HTTP_FORBIDDEN = 403;
    final static public int HTTP_NOTFOUND = 404;
    final static public int HTTP_SERVERERROR = 500;

    /**
     * Turns debug tracing on.
     */
    public void trace() {
        Debug.setTrace(true);
    }

    protected Object targetID(Object target) {
        URL url = (URL) target;
        String prot = url.getProtocol();
        String host = url.getHost();

	/* default none secure port */
        int port = 80;

	if (url.getPort() != -1) {
	    /* user specified port */
	    port = url.getPort();
	} else if (prot.toLowerCase().equals("https")) {
	    /* default secure port */
	    port = 443;
	}

        try {
            return new URL(prot + "://" + host + ":" + port + "/");
        } catch (MalformedURLException mue) {
            System.err.println(
                    "HttpManager:targetID():unable to create targetID (" +
                    mue + ")");
            return null;
        }
    }

    protected CommChannel createChannel(Object tid,
            String name) throws IOException {
        HttpChannel h;

        if (((URL) tid).getProtocol().equals("https"))
            h = new HttpsChannel(tid, name, this);
        else
            h = new HttpChannel(tid, name, this);

        return h;
    }

    /**
      * Sets the i/o buffer size of the socket underlying the HTTP channel.
      *
      * @param size the size of the input and output buffers, in bytes (the default
      *  value is 512 bytes).
      */
    public void setBufferSize(int size) {
        HttpChannel.setBufferSize(size);
        Debug.println("HttpManager> I/O buffer size set to " + size);
    }

    /**
      * Convenience routines for sending a HTTP GET, using
      * the CommManager send() call.
      *
      * @param url the destination URL.
      * @param client the CommClient to receive asynchronous updates.
      * @param arg an optional argument, passed through to the
      *  CommClient response handlers.
      * @param mode optional transaction parameters, or'd together from the following:
      *  CommManager.ASYNC_RESPONSE, CommManager.FORCE_BASIC_AUTH.
      * @param headers optional HTTP headers for this transaction.
      */
    public CommRecord get(URL url, CommClient client,
            Object arg) throws IOException {
        return send(url, client, arg, null, 0, 0);
    }
    public CommRecord get(URL url, CommClient client, Object arg,
            int mode) throws IOException {
        return send(url, client, arg, null, 0, mode);
    }
    public CommRecord get(URL url, CommClient client, Object arg,
            int mode, Preferences pref) throws IOException {
        return send(url, client, arg, null, 0, mode, null, pref);
    }
    public CommRecord get(URL url, CommClient client, Object arg,
            String[] hdrs) throws IOException {
        return send(url, client, arg, null, 0, 0, hdrs);
    }
    public CommRecord get(URL url, CommClient client, Object arg,
            int mode, String[] hdrs) throws IOException {
        return send(url, client, arg, null, 0, mode, hdrs);
    }

    /**
      * Convenience routines for sending a HTTP POST, using
      * the CommManager send() call.
      *
      * @param url the destination URL.
      * @param client the CommClient to receive asynchronous updates.
      * @param arg an optional argument, passed through to the
      *  CommClient response handlers.
      * @param data an InputStream for the data to be sent.
      * @param dataLength the length in chars of the data to be sent from the Reader.
      * @param mode optional transaction parameters, or'd together from the following:
      *  CommManager.ASYNC_RESPONSE, CommManager.FORCE_BASIC_AUTH.
      * @param headers optional HTTP headers for this transaction.
      */
    public CommRecord post(URL url, CommClient client, Object arg,
            InputStream data, int dataLength) throws IOException {
        return send(url, client, arg, data, dataLength, 0);
    }
    public CommRecord post(URL url, CommClient client, Object arg,
            InputStream data, int dataLength, int mode) throws IOException {
        return send(url, client, arg, data, dataLength, mode);
    }
    public CommRecord post(URL url, CommClient client, Object arg,
            InputStream data, int dataLength,
            String[] hdrs) throws IOException {
        return send(url, client, arg, data, dataLength, 0, hdrs);
    }
    public CommRecord post(URL url, CommClient client, Object arg,
            InputStream data, int dataLength, int mode,
            String[] hdrs) throws IOException {
        return send(url, client, arg, data, dataLength, mode, hdrs);
    }
}
