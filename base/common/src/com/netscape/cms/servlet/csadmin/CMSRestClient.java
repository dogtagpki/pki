package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Enumeration;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.conn.scheme.LayeredSchemeSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.ClientResponseFailure;
import org.jboss.resteasy.client.ProxyFactory;
import org.jboss.resteasy.client.core.BaseClientResponse;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;
import org.jboss.resteasy.client.core.extractors.ClientErrorHandler;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLSocket;

public abstract class CMSRestClient {

    protected boolean verbose;

    protected String clientCertNickname;
    protected ResteasyProviderFactory providerFactory;
    protected ClientErrorHandler errorHandler;
    protected ClientExecutor executor;
    protected URI uri;

    public CMSRestClient(String baseUri) throws URISyntaxException {
        this(baseUri, null);
    }

    // Callback to approve or deny returned SSL server certs
    // Right now, simply approve the cert.
    // ToDO: Look into taking this JSS http client code and move it into
    // its own class to be used by possible future clients.

    public CMSRestClient(String baseUri, String clientCertNick) throws URISyntaxException {

        clientCertNickname = clientCertNick;

        uri = new URI(baseUri);

        String protocol = uri.getScheme();
        int port = uri.getPort();

        DefaultHttpClient httpclient = new DefaultHttpClient();

        httpclient.addRequestInterceptor(new HttpRequestInterceptor() {
            public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
                if (verbose) System.out.println("HTTP Request: "+request.getRequestLine());
            }
        });

        httpclient.addResponseInterceptor(new HttpResponseInterceptor() {
            public void process(HttpResponse response, HttpContext context) throws HttpException, IOException {
                if (verbose) System.out.println("HTTP Response: "+response.getStatusLine());
            }
        });

        if (protocol != null && protocol.equals("https")) {

            Scheme scheme = new Scheme("https", port, new JSSProtocolSocketFactory());
            httpclient.getConnectionManager().getSchemeRegistry().register(scheme);

        }

        executor = new ApacheHttpClient4Executor(httpclient);
        providerFactory = ResteasyProviderFactory.getInstance();
        providerFactory.addClientErrorInterceptor(new CMSErrorInterceptor());
        errorHandler = new ClientErrorHandler(providerFactory.getClientErrorInterceptors());
    }

    private class ServerCertApprovalCB implements SSLCertificateApprovalCallback {

        public boolean approve(org.mozilla.jss.crypto.X509Certificate servercert,
                SSLCertificateApprovalCallback.ValidityStatus status) {

            //For now lets just accept the server cert. This is a test tool, being
            // pointed at a well know kra instance.

            SSLCertificateApprovalCallback.ValidityItem item;

            Enumeration<?> errors = status.getReasons();
            while (errors.hasMoreElements()) {
                item = (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();
                int reason = item.getReason();

                if (reason ==
                        SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER ||
                        reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {

                    //Allow these two since we haven't necessarily installed the CA cert for trust
                    // and we are choosing "localhost" as the host for this client.

                    return true;

                }
            }

            //For other errors return false

            return false;
        }
    }

    private class JSSProtocolSocketFactory implements SchemeSocketFactory, LayeredSchemeSocketFactory {

        @Override
        public Socket createSocket(HttpParams params)
                throws IOException {

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

            SSLSocket socket;

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

            if (sock == null) {
                socket = new SSLSocket(InetAddress.getByName(hostName),
                        port,
                        localAddr,
                        localPort,
                        new ServerCertApprovalCB(),
                        null);

            } else {
                socket = new SSLSocket(sock, hostName, new ServerCertApprovalCB(), null);
            }

            if (socket != null && clientCertNickname != null) {
                socket.setClientCertNickname(clientCertNickname);
            }

            return socket;
        }

        @Override
        public boolean isSecure(Socket sock) {
            //We only use this factory in the case of SSL Connections
            return true;
        }

        @Override
        public Socket createLayeredSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException,
                UnknownHostException {
            //This method implementation is required to get SSL working.
            return null;
        }

    }

    public <T> T createProxy(Class<T> clazz) {
        return ProxyFactory.create(clazz, uri, executor, providerFactory);
    }

    @SuppressWarnings("unchecked")
    public <T> T getEntity(ClientResponse<T> response) {
        BaseClientResponse<T> clientResponse = (BaseClientResponse<T>)response;
        try {
            clientResponse.checkFailureStatus();

       } catch (ClientResponseFailure e) {
            errorHandler.clientErrorHandling((BaseClientResponse<T>) e.getResponse(), e);

       } catch (RuntimeException e) {
            errorHandler.clientErrorHandling(clientResponse, e);
       }

       return response.getEntity();
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }
}
