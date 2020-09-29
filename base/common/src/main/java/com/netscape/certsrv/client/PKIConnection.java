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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.client;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.client.WebTarget;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.ProtocolException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.params.AuthPNames;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.AuthPolicy;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeLayeredSocketFactory;
import org.apache.http.conn.scheme.SchemeSocketFactory;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.impl.client.ClientParamsStack;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.EntityEnclosingRequestWrapper;
import org.apache.http.impl.client.RequestWrapper;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;

public class PKIConnection {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIConnection.class);

    ClientConfig config;

    DefaultHttpClient httpClient = new DefaultHttpClient();
    SSLCertificateApprovalCallback callback;

    ApacheHttpClient4Engine engine;
    javax.ws.rs.client.Client client;

    int requestCounter;
    int responseCounter;

    File output;

    public PKIConnection(ClientConfig config) {

        this.config = config;

        // Register https scheme.
        Scheme scheme = new Scheme("https", 443, new JSSProtocolSocketFactory());
        httpClient.getConnectionManager().getSchemeRegistry().register(scheme);

        // Don't retry operations.
        httpClient.setHttpRequestRetryHandler(new DefaultHttpRequestRetryHandler(0, false));

        if (config.getUsername() != null && config.getPassword() != null) {
            List<String> authPref = new ArrayList<String>();
            authPref.add(AuthPolicy.BASIC);
            httpClient.getParams().setParameter(AuthPNames.PROXY_AUTH_PREF, authPref);

            httpClient.getCredentialsProvider().setCredentials(
                    AuthScope.ANY,
                    new UsernamePasswordCredentials(config.getUsername(), config.getPassword()));
        }

        httpClient.addRequestInterceptor(new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {

                requestCounter++;

                logger.info("HTTP request: " + request.getRequestLine());
                for (Header header : request.getAllHeaders()) {
                    String name = header.getName();
                    String value = header.getValue();

                    if ("Authorization".equalsIgnoreCase(name)) {
                        value = "********";
                    }

                    logger.info("  " + name + ": " + value);
                }

                if (output != null) {
                    File file = new File(output, "http-request-"+requestCounter);
                    storeRequest(file, request);
                }

                // Set the request parameter to follow redirections.
                HttpParams params = request.getParams();
                if (params instanceof ClientParamsStack) {
                    ClientParamsStack paramsStack = (ClientParamsStack)request.getParams();
                    params = paramsStack.getRequestParams();
                }
                HttpClientParams.setRedirecting(params, true);
            }
        });

        httpClient.addResponseInterceptor(new HttpResponseInterceptor() {
            @Override
            public void process(HttpResponse response, HttpContext context) throws HttpException, IOException {

                responseCounter++;

                logger.info("HTTP response: " + response.getStatusLine());
                for (Header header : response.getAllHeaders()) {
                    logger.info("  " + header.getName() + ": " + header.getValue());
                }

                if (output != null) {
                    File file = new File(output, "http-response-"+responseCounter);
                    storeResponse(file, response);
                }
            }
        });

        httpClient.setRedirectStrategy(new DefaultRedirectStrategy() {
            @Override
            public HttpUriRequest getRedirect(HttpRequest request, HttpResponse response, HttpContext context)
                    throws ProtocolException {

                HttpUriRequest uriRequest = super.getRedirect(request, response, context);

                URI uri = uriRequest.getURI();
                logger.info("HTTP redirect: "+uri);

                // Redirect the original request to the new URI.
                RequestWrapper wrapper;
                if (request instanceof HttpEntityEnclosingRequest) {
                    wrapper = new EntityEnclosingRequestWrapper((HttpEntityEnclosingRequest)request);
                } else {
                    wrapper = new RequestWrapper(request);
                }
                wrapper.setURI(uri);

                return wrapper;
            }

            @Override
            public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context)
                    throws ProtocolException {

                // The default redirection policy does not redirect POST or PUT.
                // This overrides the policy to follow redirections for all HTTP methods.
                return response.getStatusLine().getStatusCode() == 302;
            }
        });

        engine = new ApacheHttpClient4Engine(httpClient);

        client = new ResteasyClientBuilder().httpEngine(engine).build();
        client.register(PKIRESTProvider.class);
    }

    public void setCallback(SSLCertificateApprovalCallback callback) {
        this.callback = callback;
    }

    public void storeRequest(File file, HttpRequest request) throws IOException {

        try (PrintStream out = new PrintStream(file)) {

            out.println(request.getRequestLine());

            for (Header header : request.getAllHeaders()) {
                out.println(header.getName()+": "+header.getValue());
            }

            out.println();

            if (request instanceof EntityEnclosingRequestWrapper) {
                EntityEnclosingRequestWrapper wrapper = (EntityEnclosingRequestWrapper) request;

                HttpEntity entity = wrapper.getEntity();
                if (entity == null) return;

                if (!entity.isRepeatable()) {
                    BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
                    wrapper.setEntity(bufferedEntity);
                    entity = bufferedEntity;
                }

                storeEntity(out, entity);
            }
        }
    }

    public void storeResponse(File file, HttpResponse response) throws IOException {

        try (PrintStream out = new PrintStream(file)) {

            out.println(response.getStatusLine());

            for (Header header : response.getAllHeaders()) {
                out.println(header.getName()+": "+header.getValue());
            }

            out.println();

            if (response instanceof BasicHttpResponse) {
                BasicHttpResponse basicResponse = (BasicHttpResponse) response;

                HttpEntity entity = basicResponse.getEntity();
                if (entity == null) return;

                if (!entity.isRepeatable()) {
                    BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
                    basicResponse.setEntity(bufferedEntity);
                    entity = bufferedEntity;
                }

                storeEntity(out, entity);
            }
        }
    }

    public void storeEntity(OutputStream out, HttpEntity entity) throws IOException {

        byte[] buffer = new byte[1024];
        int c;

        try (InputStream in = entity.getContent()) {
            while ((c = in.read(buffer)) > 0) {
                out.write(buffer, 0, c);
            }
        }
    }

    private class JSSProtocolSocketFactory implements SchemeSocketFactory, SchemeLayeredSocketFactory {

        @Override
        public Socket createSocket(HttpParams params) throws IOException {
            return null;
        }

        @Override
        public Socket connectSocket(Socket sock,
                InetSocketAddress remoteAddress,
                InetSocketAddress localAddress,
                HttpParams params)
                throws IOException,
                UnknownHostException,
                ConnectTimeoutException {

            // Make sure certificate database is already initialized,
            // otherwise SSLSocket will throw UnsatisfiedLinkError.
            try {
                CryptoManager.getInstance();

            } catch (NotInitializedException e) {
                throw new Error("Certificate database not initialized.", e);
            }

            String hostName = null;
            int port = 0;
            if (remoteAddress != null) {
                hostName = remoteAddress.getHostName();
                port = remoteAddress.getPort();
            }

            int localPort = 0;
            InetAddress localAddr = null;

            if (localAddress != null) {
                localPort = localAddress.getPort();
                localAddr = localAddress.getAddress();
            }

            SSLSocket socket;
            if (sock == null) {
                socket = new SSLSocket(InetAddress.getByName(hostName),
                        port,
                        localAddr,
                        localPort,
                        callback,
                        null);

            } else {
                socket = new SSLSocket(sock, hostName, callback, null);
            }

            String certNickname = config.getCertNickname();
            if (certNickname != null) {
                logger.info("Client certificate: "+certNickname);
                socket.setClientCertNickname(certNickname);
            }

            socket.addSocketListener(new SSLSocketListener() {

                @Override
                public void alertReceived(SSLAlertEvent event) {

                    int intLevel = event.getLevel();
                    SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                    int intDescription = event.getDescription();
                    SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                    if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                        logger.error(level + ": SSL alert received: " + description);
                    }
                }

                @Override
                public void alertSent(SSLAlertEvent event) {

                    int intLevel = event.getLevel();
                    SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                    int intDescription = event.getDescription();
                    SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                    if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                        logger.error(level + ": SSL alert sent: " + description);
                    }
                }

                @Override
                public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
                }

            });
            return socket;
        }

        @Override
        public boolean isSecure(Socket sock) {
            // We only use this factory in the case of SSL Connections.
            return true;
        }

        @Override
        public Socket createLayeredSocket(Socket socket, String target, int port, HttpParams params)
                throws IOException, UnknownHostException {
            // This method implementation is required to get SSL working.
            return null;
        }

    }

    public WebTarget target(String path) throws Exception {
        String uri = config.getServerURL().toString();
        if (path != null) {
            uri += path;
        }
        return client.target(uri);
    }

    public File getOutput() {
        return output;
    }

    public void setOutput(File output) {
        this.output = output;
    }
}
