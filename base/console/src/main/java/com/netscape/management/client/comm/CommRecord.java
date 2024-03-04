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
 * This class encapsulates a single asynchronous communication
 * request.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.3, 10/6/97
 * @see     CommChannel
 * @see     CommClient
 * @see     CommManager
 */
public class CommRecord {
    public final static String WAITING = "Waiting";
    public final static String ASSIGNED = "Assigned";
    public final static String SENT = "Sent";
    public final static String COMPLETE = "Complete";
    public final static String ERROR = "Error";

    protected CommClient client;
    protected CommChannel channel;
    protected Object arg;
    protected Object tid;
    protected Object target;
    protected InputStream data;
    protected int dlen;
    protected Object status;
    protected boolean async;
    protected Object auth;
    protected int mode;
    protected Object charg;

    /**
     * Creates a CommRecord instance with the given parameters.
     *
     * @param _client the object implementing the CommClient interface to which
     *  response and error handler calls will be made.
     * @param _arg an optional argument for use by the CommClient _client.
     * @param _tid the internal targetID of the request.
     * @param _target the external target descriptor.
     * @param _data an InputStream for the data associated with the request.
     * @param _dlen the length in chars of the data to be read from the reader.
     * @param _mode the CommChannel mode argument.
     * @param _charg the CommChannel data argument.
     */
    public CommRecord(CommClient _client, Object _arg, Object _tid,
            Object _target, InputStream _data, int _dlen, int _mode,
            Object _charg) {
        client = _client;
        channel = null;
        arg = _arg;
        tid = _tid;
        target = _target;
        data = _data;
        dlen = _dlen;
        status = null;
        async = false;
        auth = null;
        mode = _mode;
        charg = _charg;
    }

    public CommClient getClient() {
        return client;
    }
    public CommChannel getChannel() {
        return channel;
    }
    public Object getArg() {
        return arg;
    }
    public Object getTID() {
        return tid;
    }
    public Object getTarget() {
        return target;
    }
    public InputStream getData() {
        return data;
    }
    public int getDataLength() {
        return dlen;
    }
    public Object getStatus() {
        return status;
    }
    public Object getAuthObj() {
        return auth;
    }
    public int getMode() {
        return mode;
    }
    public Object getChannelArg() {
        return charg;
    }

    public void setChannel(CommChannel chan) {
        channel = chan;
    }
    public void setTarget (Object targ) {
        target = targ;
    }
    public void setStatus (Object stat) {
        status = stat;
    }
    public void setAuthObj(Object aobj) {
        auth = aobj;
    }

    /**
      * The asynchronous response mode determines how response callbacks
      * are handled by a CommChannel processing this CommRecord. If set
      * for asynchronous mode, the response handler will be called immediately
      * upon sending the request, with a blocking InputStream to access the
      * response. If not set (the default), the response handler will be called
      * after the entire response has been received, with a non-blocking InputStream
      * to access the buffered response.
      */
    public void setAsyncResponseMode() {
        async = true;
    }
    public boolean getAsyncResponseMode() {
        return async;
    }

    public String toString() {
        return "CommRecord:\n" + "client:       " + client + "\n" +
                "channel:      " + channel + "\n" + "arg:          " +
                arg + "\n" + "tid:          " + tid + "\n" +
                "target:       " + target + "\n" + "data:         " +
                data + "\n" + "data length:  " + dlen + "\n" +
                "status:       " + status + "\n" + "auth object:  " +
                auth + "\n" + "channel mode: " + mode + "\n" +
                "channel arg:  " + charg + "\n" + "async response: " +
                async;
    }
}
