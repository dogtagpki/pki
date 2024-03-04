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

import java.io.IOException;
import java.io.InputStream;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import com.netscape.management.client.preferences.Preferences;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LinkedList;
import com.netscape.management.client.util.LinkedListElement;

/**
 * This abstract class is the superclass of all classes which
 * attempt to perform communication channel management and
 * transaction processing. Subclasses implement the createChannel()
 * and targetID() methods, usually in a manner specific to the
 * type of communication channels being managed.
 *
 * @see     CommChannel
 * @see     CommClient
 * @see     CommRecord
 */
public abstract class CommManager {
    public static final int ASYNC_RESPONSE = 0x1;
    public static final int FORCE_BASIC_AUTH = 0x2;

    public static final int NO_TIMEOUT = -1;
    public static final int DEFAULT_RESPONSE_TIMEOUT = 30000;
    public static final int DEFAULT_IDLE_TIMEOUT = 1000;

    public static String BasicAuth = "Basic Auth Request";

    protected static int CommChannelCount = 0;

    protected LinkedList requests = null;
    protected Hashtable channels = null;
    protected int idleTimeout = DEFAULT_IDLE_TIMEOUT;
    protected int responseTimeout = DEFAULT_RESPONSE_TIMEOUT;
    protected int maxChannels = 1;

    protected static String language = "en";
    protected static boolean sendUTF8 = true;

    private IOException channelException;

    /**
     * Creates a new communication manager instance and initializes
     * its internal systems.
     *
     */
    protected CommManager() {
        requests = new LinkedList();
        channels = new Hashtable();
        language = Locale.getDefault().getLanguage();
    }

    /**
      * Enqueues an asynchronous communication request. Performs communication
      * channel management as necessary, according to tunable parameters.
      *
      * @param target the communication channel target, usually specific to the communication
      *  channel type under management.
      * @param client an object implementing the CommClient interface to receive responses and errors
      *  from this transaction.
      * @param arg an optional argument for use by the CommClient. Will be available in the CommRecord
      *  object passed to the CommClient handler methods.
      * @param data an InputStream for data to be sent via the communication channel.
      * @param dataLength the length in chars of the data to be read from the data InputStream.
      * @param mode optional transaction arguments for the CommChannel, or'd together from:
      *  ASYNC_RESPONSE, which specifies
      *  that the CommClient response handler will be called immediately after the
      *  request has been sent, with a blocking Input Stream to access the response; otherwise the
      *  response handler will be called after the entire response has been received and buffered, with
      *  a non-blocking Input Stream to access the buffered response.
      *  FORCE_BASIC_AUTH, which specifies
      *  that basic auth information will be sent with the transaction; otherwise the transaction will be
      *  first attempted without basic auth, and retried if necessary on receipt of an auth request.
      * @param channelData optional data argument to be passed to the CommChannel.
      * @param pref preferences containing max and min SSL versions
      * @see CommClient
      * @see CommRecord
      * @see CommChannel
      */
    public synchronized CommRecord send(Object target,
            CommClient client, Object arg, InputStream data,
            int dataLength, int mode, Object channelData, Preferences pref)
        throws IOException {
        Debug.println("CommManager> New CommRecord (" + target + ")");
        Debug.println(Debug.TYPE_HTTP,
                ((data == null) ? "GET  " : "POST ") + target);

        Object tid = targetID(target);
        Vector chv = (Vector)(channels.get(tid));

        if (chv == null)
            channels.put(tid, chv = new Vector());

        int i = 0;
        for (; i < chv.size(); i++) {
            CommChannel cc = (CommChannel)(chv.elementAt(i));

            if (cc.ready())
                break;
        }

        if ((i == chv.size()) && (i < maxChannels)) {
            CommChannel cc = createChannel(tid,
                    Integer.toString(CommChannelCount++) + ":" +
                    Integer.toString(i));
            cc.open(pref);
            chv.addElement(cc);
        }

        CommRecord cr = new CommRecord(client, arg, tid, target, data,
                dataLength, mode, channelData);
        cr.setStatus(CommRecord.WAITING);
        if ((mode & ASYNC_RESPONSE) != 0)
            cr.setAsyncResponseMode();
        if ((mode & FORCE_BASIC_AUTH) != 0)
            cr.setAuthObj(BasicAuth);
        requests.append(cr);
        notifyAll();
        return (cr);
    }

    public synchronized CommRecord send(Object target,
            CommClient client, Object arg, InputStream data, int dataLength)
        throws IOException {
        return send(target, client, arg, data, dataLength, 0, null, null);
    }

    public synchronized CommRecord send(Object target,
            CommClient client, Object arg, InputStream data,
            int dataLength, int mode)
        throws IOException {
        return send(target, client, arg, data, dataLength, mode, null, null);
    }

    public synchronized CommRecord send(Object target,
            CommClient client, Object arg, InputStream data,
            int dataLength, int mode, String[] headers)
        throws IOException {
        return send(target, client, arg, data, dataLength, mode, null, null);
    }

    public synchronized CommRecord send(Object target,
            CommClient client, Object arg, InputStream data,
            int dataLength, int mode, Preferences pref)
        throws IOException {
        return send(target, client, arg, data, dataLength, mode, null, pref);
    }
    /**
      * Forcibly terminates a communication request. If the request is in the queue,
      * it is dequeued. If the request is in progress, an attempt is made to halt
      * the request at the next available opportunity. If the request has completed,
      * no action is taken.
      *
      * @param cr the CommRecord of the request to be terminated.
      * @returns true if the request was terminated, false if the request has already completed.
      * @throws IOException if an I/O error occurs.
      */
    public synchronized boolean terminate(CommRecord cr)
        throws IOException {
        Object status = cr.getStatus();

        if (status.equals(CommRecord.COMPLETE) || status.equals(CommRecord.ERROR)) {
            Debug.println("CommManager> Terminate request for " +
                    cr.getTarget() + " in " + status + " state. Ignored");
            return false;
        }

        if (status.equals(CommRecord.WAITING)) {
            requests.remove(cr);
            Debug.println("CommManager> " + cr.getTarget() + " removed from the queue");
            return true;
        }

        if (status.equals(CommRecord.ASSIGNED) || status.equals(CommRecord.SENT)) {
            CommChannel cc = cr.getChannel();

            if (cc == null)
                Debug.println("CommManager> Terminate request for " +
                        cr.getTarget() + ", unable to close CommChannel");

            closeChannel(cc);
            Debug.println("CommManager> " + cr.getTarget() + " terminated");
            return true;
        }

        Debug.println("CommManager> Terminate request for " +
                cr.getTarget() + ", state unknown");
        return false;
    }

    /**
      * Sets the maximum number of concurrent communication channels that can
      * be open to a single target at any instance. The default value is 1.
      *
      * @param num the maximum number of concurrent communication channels.
      */
    public void setMaxChannels(int num) {
        maxChannels = num;
    }

    /**
      * Sets the channel idle timeout period.
      * @deprecated Use setIdleTimeout(int)
      * @param ms the idle timeout period in milliseconds.
      */
    @Deprecated
    public void setTimeout(int ms) {
        setIdleTimeout(ms);
    }

    /**
      * Sets the channel idle timeout period. Any managed communication
      * channel that remains idle for this period will be closed and released
      * from management. The special value NO_TIMEOUT can be used to specify
      * that there should be no timeout.
      *
      * @param ms the idle timeout period in milliseconds.
      */
    public void setIdleTimeout(int ms) {
        idleTimeout = ms;
    }

    /**
      * Returns the channel idle timeout period.
      * @return the channel idle timeout period in milliseconds.
      */
    public int getIdleTimeout() {
        return idleTimeout;
    }

    /**
      * Sets the maximum time to wait for the response from the server.
      * After a request has been sent, if the server does not respond
      * within the response timeout, the CommChannel will throw
      * InterruptedIOException. The default value is DEFAULT_RESPONSE_TIMEOUT.
      *
      * @param ms the response timeout period in milliseconds.
      */
    public void setResponseTimeout(int ms) {
        responseTimeout = ms;
    }

    /**
      * Returns the response timeout period.
      * @return the response timeout period in milliseconds.
      */
    public int getResponseTimeout() {
        return responseTimeout;
    }

    /**
      * Dequeues and returns the next asynchronous communication request
      * from the front of the queue. This method is meant to be called
      * repeatedly by communication channel objects to process requests
      * in the queue.
      *
      * @param cc an object implementing the CommChannel interface, and the
      *  caller of this method. An idle timeout of the communication channel
      *  will be processed via this parameter.
      * @throws IOException if an I/O error occurs.
      */
    protected synchronized CommRecord next(CommChannel cc)
        throws IOException {
        boolean timedout = false;
        Object tid = cc.targetID();

        while (true) {
            for (LinkedListElement p = requests.head ; p != null ;
                    p = p.next) {
                CommRecord cr = (CommRecord)(p.obj);

                if (cr.getTID().equals(tid)) {
                    requests.remove(cr);
                    cr.setStatus(CommRecord.ASSIGNED);
                    return (cr);
                }
            }

            if (timedout) {
                closeChannel(cc);
                return (null);
            }

            if (idleTimeout == NO_TIMEOUT) {
                try {
                    wait();
                } catch (InterruptedException e) { }
                continue;
            }

            long now = System.currentTimeMillis();

            try {
                wait(idleTimeout);
            } catch (InterruptedException e) { }

            if ((System.currentTimeMillis() - now) > idleTimeout)
                timedout = true;
        }
    }

    /**
      * Returns an asynchronous communication request to the head of the queue.
      * This method is meant to be called by communication channel objects to
      * retry an asynchronous communication request. Performs communication
      * channel management as necessary, according to tunable parameters.
      *
      * @param cr the CommRecord representing the request to be retried.
      * @see CommClient
      * @see CommRecord
      * @see CommChannel
      */
    protected synchronized void retry(CommRecord cr)
        throws IOException {
        Debug.println("CommManager> Retry CommRecord (" +
                cr.getTarget() + ")");

        Object tid = cr.getTID();
        Vector chv = (Vector)(channels.get(tid));

        if (chv == null)
            channels.put(tid, chv = new Vector());

        int i = 0;
        for (; i < chv.size(); i++) {
            CommChannel cc = (CommChannel)(chv.elementAt(i));

            if (cc.ready())
                break;
        }

        if ((i == chv.size()) && (i < maxChannels)) {
            CommChannel cc = createChannel(tid,
                    Integer.toString(CommChannelCount++) + ":" +
                    Integer.toString(i));
            cc.open();
            chv.addElement(cc);
        }

        cr.setStatus(CommRecord.WAITING);
        if (cr.getData() != null)
            cr.getData().reset();
        requests.prepend(cr);
        notifyAll();
    }


    /**
      * Forcibly removes a communication channel from the management set.
      *
      * @param cc an object implementing the CommChannel interface, and the
      *  caller of this method.
      * @throws IOException if an I/O error occurs.
      */
    protected synchronized void closeChannel(CommChannel cc)
        throws IOException {
        Vector chv;
        Object tid = cc.targetID();

        if ((chv = (Vector)(channels.get(tid))) == null)
            return;

        chv.removeElement(cc);

        // There could be requests in the queue for this tid, so we need to check
        // and re-open the channel, if necessary.

        for (LinkedListElement p = requests.head ; p != null ; p = p.next) {
            CommRecord cr = (CommRecord)(p.obj);

            if (cr.getTID().equals(tid)) {
                // There is at least one other request for this tid, so we need
                // to re-open a channel with this tid. We can guarantee that we're not
                // exceeding maxChannels, since we just closed an open channel.

                CommChannel newcc = createChannel(tid,
                        Integer.toString(CommChannelCount++) + ":" +
                        Integer.toString(chv.size()));
                newcc.open();
                chv.addElement(newcc);
            }
        }

        if (chv.size() == 0)
            channels.remove(tid);

        cc.close();
        // cc.close must be the last operation in closeChannel(), since close() calls thread.stop() on the
        // CommChannel thread, which is sometimes used to call closeChannel()...
    }

    /**
      * Sets the language attribute, to specify acceptable languages.
      *
      * @param language the language String in ISO format.
      */
    public static void setLanguage(String _language) {
        language = _language;
    }

    /**
      * Gets the language attribute, to specify acceptable languages.
      *
      * @return the language String in ISO format.
      */
    public static String getLanguage() {
        return language;
    }

    /**
      * Sets the sendUTF8 attribute, to specify that URIs, usernames, and passwords
      * should be converted to UTF-8 before tranmission. By default, conversion
      * is disabled.
      *
      * @param _sendUTF8 true to enable UTF-8 conversion, false to disable it.
      */
    public static void setSendUTF8(boolean _sendUTF8) {
        sendUTF8 = _sendUTF8;
    }

    /**
      * Gets the sendUTF8 attribute, which specifies that URIs, usernames, and passwords
      * should be converted to UTF-8 before tranmission.
      *
      * @return the boolean value, true to enable UTF-8 conversion, false to disable it.
      */
    public static boolean getSendUTF8() {
        return sendUTF8;
    }

    /**
      * Returns the internal representation of the communication channel target, specific to the
      * type of communication channel under management.
      *
      * @param target the external communication target descriptor.
      */
    protected abstract Object targetID(Object target);

    /**
     * Creates a new communication channel instance to the given targetID, usually specific
     * to the type of communication channels under management. The name parameter specifies
     * a label that will appear in the tracing output.
     *
     * @param tid the targetID of the connection target, usually specific to the communication
     *  channel class being created.
     * @param name a string label which will appear in tracing output.
     * @throws IOException if an I/O error occurs.
     */
    protected abstract CommChannel createChannel(Object tid,
            String name) throws IOException;
}
