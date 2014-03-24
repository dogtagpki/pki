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
package com.netscape.cmscore.connector;

import java.io.IOException;
import java.util.StringTokenizer;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.connector.IHttpConnection;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.connector.IRemoteAuthority;
import com.netscape.certsrv.connector.IRequestEncoder;
import com.netscape.cmscore.util.Debug;
import com.netscape.cmsutil.http.HttpClient;
import com.netscape.cmsutil.http.HttpRequest;
import com.netscape.cmsutil.http.HttpResponse;
import com.netscape.cmsutil.net.ISocketFactory;

public class HttpConnection implements IHttpConnection {
    protected IRemoteAuthority mDest = null;
    protected HttpRequest mHttpreq = new HttpRequest();
    protected IRequestEncoder mReqEncoder = null;
    protected HttpClient mHttpClient = null;

    protected boolean Connect(String host, HttpClient client) {
        StringTokenizer st = new StringTokenizer(host, " ");
        while (st.hasMoreTokens()) {
            String hp = st.nextToken(); // host:port
            StringTokenizer st1 = new StringTokenizer(hp, ":");
            try {
                String h = st1.nextToken();
                int p = Integer.parseInt(st1.nextToken());
                client.connect(h, p);
                return true;
            } catch (Exception e) {
                // may want to log the failure
            }
            try {
                Thread.sleep(5000); // 5 seconds
            } catch (Exception e) {
            }

        }
        return false;
    }

    public void setRequestURI(String uri)
            throws EBaseException {
        mHttpreq.setURI(uri);
    }

    public String getRequestURI() {
        return mHttpreq.getURI();
    }

    public HttpConnection(IRemoteAuthority dest, ISocketFactory factory) {
        mDest = dest;
        mReqEncoder = new HttpRequestEncoder();
        mHttpClient = new HttpClient(factory);
        if (Debug.ON)
            Debug.trace("Created HttpClient");
        try {
            mHttpreq.setMethod("POST");
            // in case of multi-uri, uri will be set right before send
            //   by calling setRequestURI(uri)
            if (mDest.getURI() != null)
                mHttpreq.setURI(mDest.getURI());

            String contentType = dest.getContentType();
            if (contentType != null) {
                CMS.debug("HttpConnection: setting Content-Type");
                mHttpreq.setHeader("Content-Type", contentType );
            }

            mHttpreq.setHeader("Connection", "Keep-Alive");
            CMS.debug("HttpConnection: connecting to " + dest.getHost() + ":" + dest.getPort());
            String host = dest.getHost();
            // we could have a list of host names in the host parameters
            // the format is, for example,
            // "directory.knowledge.com:1050 people.catalog.com 199.254.1.2"
            if (host != null && host.indexOf(' ') != -1) {
                // try to do client-side failover
                boolean connected = false;
                do {
                    connected = Connect(host, mHttpClient);
                } while (!connected);
            } else {
                mHttpClient.connect(host, dest.getPort());
            }
            CMS.debug("HttpConnection: connected to " + dest.getHost() + ":" + dest.getPort());
        } catch (IOException e) {
            // server's probably down. that's fine. try later.
            //System.out.println(
            //"Can't connect to server in connection creation");
        }
    }

    /*
     * @param op operation to determine the receiving servlet (multi-uri support)
     */
    public HttpConnection(IRemoteAuthority dest, ISocketFactory factory, int timeout) {
        mDest = dest;
        mReqEncoder = new HttpRequestEncoder();
        mHttpClient = new HttpClient(factory);
        CMS.debug("HttpConn:Created HttpConnection: factory " + factory + "client " + mHttpClient);
        try {
            mHttpreq.setMethod("POST");
            // in case of multi-uri, uri will be set right before send
            //   by calling setRequestURI(op)
            if (mDest.getURI() != null)
                mHttpreq.setURI(mDest.getURI());

            String contentType = dest.getContentType();
            if (contentType != null) {
                CMS.debug("HttpConnection: setting Content-Type");
                mHttpreq.setHeader("Content-Type", contentType );
            }

            mHttpreq.setHeader("Connection", "Keep-Alive");
            CMS.debug("HttpConnection: connecting to " + dest.getHost() + ":" + dest.getPort() + " timeout:" + timeout);
            mHttpClient.connect(dest.getHost(), dest.getPort(), timeout);
            CMS.debug("HttpConnection: connected to " + dest.getHost() + ":" + dest.getPort() + " timeout:" + timeout);
        } catch (IOException e) {
            // server's probably down. that's fine. try later.
            //System.out.println(
            //"Can't connect to server in connection creation");
            CMS.debug("CMSConn:IOException in creating HttpConnection " + e.toString());
        }
    }

    // Insert end
    /**
     * sends a request to remote RA/CA, returning the result.
     *
     * @throws EBaseException if request could not be encoded
     */
    public IPKIMessage send(IPKIMessage tomsg)
            throws EBaseException {
        IPKIMessage replymsg = null;
        HttpResponse resp = null;

        CMS.debug("in HttpConnection.send " + this);
        if (Debug.ON)
            Debug.trace("encoding request ");

        String content = null;

        try {
            content = mReqEncoder.encode(tomsg);
        } catch (IOException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "Could not encode request"));
        }
        if (Debug.ON) {
            Debug.trace("encoded request");
            Debug.trace("------ " + content.length() + "-----");
            Debug.trace(content);
            Debug.trace("--------------------------");
        }
        resp = doSend(content);

        // decode reply.
        // if reply is bad, error is thrown and request will be resent
        String pcontent = resp.getContent();

        if (Debug.ON) {
            Debug.trace("Server returned\n");
            Debug.trace("-------");
            Debug.trace(pcontent);
            Debug.trace("-------");
        }
        CMS.debug("HttpConnection.send response: " + pcontent);

        try {
            replymsg = (IPKIMessage) mReqEncoder.decode(pcontent);
        } catch (IOException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "Could not decode content"));
        }
        CMS.debug("HttpConn:decoded reply");
        return replymsg;
    }

    /**
     * sends a request to a remote authority, returning the result.
     * @author cfu (multi-uri support)
     * @throws EBaseException for any failure
     */
    public HttpResponse send(String content)
            throws EBaseException {
        HttpResponse resp = null;
        if ((content == null) || content.equals("")) {
            CMS.debug("HttpConnection.send: with String content: null or empty");
            throw new EBaseException("HttpConnection.send: with String content: null or empty");
        }
        // CMS.debug("HttpConnection.send: with String content: " + content);

        resp = doSend(content);
        return resp;
    }

    private HttpResponse doSend(String content)
            throws EBaseException {
        HttpResponse resp = null;
        boolean reconnect = false;

        if (getRequestURI() == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "URI not set in HttpRequest"));
        }

        mHttpreq.setHeader("Content-Length",
                Integer.toString(content.length()));
        CMS.debug("HttpConnection.doSend: with String content length: " + Integer.toString(content.length()));
        mHttpreq.setContent(content);

        try {
            if (!mHttpClient.connected()) {
                mHttpClient.connect(mDest.getHost(), mDest.getPort());
                CMS.debug("HttpConnection.doSend: reconnected to " + mDest.getHost() + ":" + mDest.getPort());
                reconnect = true;
            }
        } catch (IOException e) {
            if (e.getMessage().indexOf("Peer's certificate issuer has been marked as not trusted") != -1) {
                throw new EBaseException(
                        CMS.getUserMessage(
                                "CMS_BASE_CONN_FAILED",
                                "(This local authority cannot connect to the remote authority. The local authority's signing certificate must chain to a CA certificate trusted for client authentication in the certificate database. Use the certificate manager, or command line tool such as certutil to verify that the trust permissions of the local authority's issuer cert have 'CT' setting in the SSL client auth field.)"));
            }
            CMS.debug("HttpConn:Couldn't reconnect " + e);
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED", "Couldn't reconnect " + e));
        }

        // if remote closed connection want to reconnect and resend.
        while (resp == null) {
            try {
                CMS.debug("HttpConnection.doSend: sending request");
                resp = mHttpClient.send(mHttpreq);
            } catch (IOException e) {
                CMS.debug("HttpConn: mHttpClient.send failed " + e.toString());
                if (reconnect) {
                    CMS.debug("HttpConnection.doSend:resend failed again. " + e);
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED", "resend failed again. " + e));
                }
                try {
                    CMS.debug("HttpConnection.doSend: trying a reconnect ");
                    mHttpClient.connect(mDest.getHost(), mDest.getPort());
                } catch (IOException ex) {
                    CMS.debug("HttpConnection.doSend: reconnect for resend failed. " + ex);
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED", "reconnect for resend failed."
                            + ex));
                }
                reconnect = true;
            }
        } //while

        // got reply; check status
        String statusStr = resp.getStatusCode();

        CMS.debug("HttpConnection.doSend:server returned status " + statusStr);
        int statuscode = -1;

        try {
            statuscode = Integer.parseInt(statusStr);
        } catch (NumberFormatException e) {
            statuscode = -1;
        }

        /* HttpServletResponse.SC_OK = 200 */
        if (statuscode != 200) {

            /* HttpServletResponse.SC_UNAUTHORIZED = 401 */
            if (statuscode == 401) {
                // XXX what to do here.
                String msg = "request no good " + statuscode + " " + resp.getReasonPhrase();

                CMS.debug(msg);
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_AUTHENTICATE_FAILED", msg));
            } else {
                // XXX what to do here.
                String msg = "HttpConn:request no good " + statuscode + " " + resp.getReasonPhrase();

                CMS.debug(msg);
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", msg));
            }
        }
        return resp;
    }
}
