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

    public HttpConnection(IRemoteAuthority dest, ISocketFactory factory) {
        mDest = dest;
        mReqEncoder = new HttpRequestEncoder();
        mHttpClient = new HttpClient(factory);
        if (Debug.ON)
            Debug.trace("Created HttpClient");
        try {
            mHttpreq.setMethod("POST");
            mHttpreq.setURI(mDest.getURI());
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

    // Inserted by beomsuk
    public HttpConnection(IRemoteAuthority dest, ISocketFactory factory, int timeout) {
        mDest = dest;
        mReqEncoder = new HttpRequestEncoder();
        mHttpClient = new HttpClient(factory);
        CMS.debug("HttpConn:Created HttpConnection: factory " + factory + "client " + mHttpClient);
        try {
            mHttpreq.setMethod("POST");
            mHttpreq.setURI(mDest.getURI());
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
        boolean reconnect = false;

        mHttpreq.setHeader("Content-Length",
                Integer.toString(content.length()));
        if (Debug.ON)
            Debug.trace("request encoded length " + content.length());
        mHttpreq.setContent(content);

        HttpResponse p = null;

        try {
            if (!mHttpClient.connected()) {
                mHttpClient.connect(mDest.getHost(), mDest.getPort());
                CMS.debug("HttpConn:reconnected to " + mDest.getHost() + ":" + mDest.getPort());
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
        while (p == null) {
            try {
                if (Debug.ON)
                    Debug.trace("sending request");
                p = mHttpClient.send(mHttpreq);
            } catch (IOException e) {
                CMS.debug("HttpConn: mHttpClient.send failed " + e.toString());
                if (reconnect) {
                    CMS.debug("HttpConn:resend failed again. " + e);
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED", "resend failed again. " + e));
                }
                try {
                    CMS.debug("HttpConn: trying a reconnect ");
                    mHttpClient.connect(mDest.getHost(), mDest.getPort());
                } catch (IOException ex) {
                    CMS.debug("reconnect for resend failed. " + ex);
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED", "reconnect for resend failed."
                            + ex));
                }
                reconnect = true;
            }
        }

        // got reply; check status
        String statusStr = p.getStatusCode();

        CMS.debug("HttpConn:server returned status " + statusStr);
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
                String msg = "request no good " + statuscode + " " + p.getReasonPhrase();

                if (Debug.ON)
                    Debug.trace(msg);
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_AUTHENTICATE_FAILED", msg));
            } else {
                // XXX what to do here.
                String msg = "HttpConn:request no good " + statuscode + " " + p.getReasonPhrase();

                CMS.debug(msg);
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", msg));
            }
        }

        // decode reply.
        // if reply is bad, error is thrown and request will be resent
        String pcontent = p.getContent();

        if (Debug.ON) {
            Debug.trace("Server returned\n");
            Debug.trace("-------");
            Debug.trace(pcontent);
            Debug.trace("-------");
        }

        try {
            replymsg = (IPKIMessage) mReqEncoder.decode(pcontent);
        } catch (IOException e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "Could not decode content"));
        }
        CMS.debug("HttpConn:decoded reply");
        return replymsg;
    }
}
