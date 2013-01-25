package com.netscape.certsrv.client;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.ws.rs.core.MediaType;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.http.Header;
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
import org.apache.http.conn.scheme.LayeredSchemeSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeSocketFactory;
import org.apache.http.impl.client.ClientParamsStack;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.EntityEnclosingRequestWrapper;
import org.apache.http.impl.client.RequestWrapper;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.jboss.resteasy.client.ClientExecutor;
import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.client.ClientResponse;
import org.jboss.resteasy.client.ClientResponseFailure;
import org.jboss.resteasy.client.ProxyFactory;
import org.jboss.resteasy.client.core.BaseClientResponse;
import org.jboss.resteasy.client.core.executors.ApacheHttpClient4Executor;
import org.jboss.resteasy.client.core.extractors.ClientErrorHandler;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLSocket;


public class PKIConnection {

    boolean verbose;

    ClientConfig config;

    DefaultHttpClient httpClient = new DefaultHttpClient();

    ResteasyProviderFactory providerFactory;
    ClientErrorHandler errorHandler;
    ClientExecutor executor;

    public PKIConnection(ClientConfig config) {
        this.config = config;

        // Register https scheme.
        Scheme scheme = new Scheme("https", 443, new JSSProtocolSocketFactory());
        httpClient.getConnectionManager().getSchemeRegistry().register(scheme);

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
                if (verbose) {
                    System.out.println("HTTP request: "+request.getRequestLine());
                    for (Header header : request.getAllHeaders()) {
                        System.out.println("  "+header.getName()+": "+header.getValue());
                    }
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
                if (verbose) {
                    System.out.println("HTTP response: "+response.getStatusLine());
                    for (Header header : response.getAllHeaders()) {
                        System.out.println("  "+header.getName()+": "+header.getValue());
                    }
                }
            }
        });

        httpClient.setRedirectStrategy(new DefaultRedirectStrategy() {
            @Override
            public HttpUriRequest getRedirect(HttpRequest request, HttpResponse response, HttpContext context)
                    throws ProtocolException {

                HttpUriRequest uriRequest = super.getRedirect(request, response, context);

                URI uri = uriRequest.getURI();
                if (verbose) System.out.println("HTTP redirect: "+uri);

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

        executor = new ApacheHttpClient4Executor(httpClient);
        providerFactory = ResteasyProviderFactory.getInstance();
        providerFactory.addClientErrorInterceptor(new PKIErrorInterceptor());
        errorHandler = new ClientErrorHandler(providerFactory.getClientErrorInterceptors());
    }

    private class ServerCertApprovalCB implements SSLCertificateApprovalCallback {
        // NOTE:  The following helper method defined as
        //        'public String displayReason(int reason)'
        //        should be moved into the JSS class called
        //        'org.mozilla.jss.ssl.SSLCertificateApprovalCallback'
        //        under its nested subclass called 'ValidityStatus'.

        // While all reason values should be unique, this method has been
        // written to return the name of the first defined reason that is
        // encountered which contains the requested value, or null if no
        // reason containing the requested value is encountered.
        public String displayReason(int reason) {
            Class<SSLCertificateApprovalCallback.ValidityStatus> c =
                SSLCertificateApprovalCallback.ValidityStatus.class;
            for (Field f : c.getDeclaredFields()) {
                int mod = f.getModifiers();
                if (Modifier.isStatic(mod) &&
                    Modifier.isPublic(mod) &&
                    Modifier.isFinal(mod)) {
                    try {
                        int value = f.getInt(null);
                        if (value == reason) {
                            return f.getName();
                        }
                    } catch (IllegalAccessException e) {
                        e.printStackTrace();
                    }
                }
            }

            return null;
        }

        // Callback to approve or deny returned SSL server cert.
        // Right now, simply approve the cert.
        public boolean approve(org.mozilla.jss.crypto.X509Certificate serverCert,
                SSLCertificateApprovalCallback.ValidityStatus status) {

            boolean approval = true;
            String reasonName = null;

            if (verbose) System.out.println("Server certificate: "+serverCert.getSubjectDN());

            SSLCertificateApprovalCallback.ValidityItem item;

            // If there are no items in the Enumeration returned by
            // getReasons(), you can assume that the certificate is
            // trustworthy, and return true to allow the connection to
            // continue, or you can continue to make further tests of
            // your own to determine trustworthiness.
            Enumeration<?> errors = status.getReasons();
            while (errors.hasMoreElements()) {
                item = (SSLCertificateApprovalCallback.ValidityItem) errors.nextElement();
                int reason = item.getReason();

                if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER) {
                    // Ignore the "UNTRUSTED_ISSUER" validity status
                    // during PKI instance creation since we are
                    // utilizing an untrusted temporary CA cert.
                    if (!config.InstanceCreationMode) {
                        // Otherwise, issue a WARNING, but allow this process
                        // to continue since we haven't installed a trusted CA
                        // cert for this operation.
                        System.err.println("WARNING: UNTRUSTED ISSUER encountered on '"+serverCert.getSubjectDN()+"' indicates a non-trusted CA cert");
                    }
                } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {
                    // Issue a WARNING, but allow this process to continue on
                    // common-name mismatches.
                    System.err.println("WARNING: BAD_CERT_DOMAIN encountered on '"+serverCert.getSubjectDN()+"' indicates a common-name mismatch");
                } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID) {
                    // Ignore the "CA_CERT_INVALID" validity status
                    // during PKI instance creation since we are
                    // utilizing an untrusted temporary CA cert.
                    if (!config.InstanceCreationMode) {
                        // Otherwise, set approval false to deny this
                        // certificate so that the connection is terminated.
                        // (Expect an IOException on the outstanding
                        //  read()/write() on the socket).
                        System.err.println("ERROR: CA_CERT_INVALID encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!");
                        approval = false;
                    }
                } else {
                    // Set approval false to deny this certificate so that
                    // the connection is terminated. (Expect an IOException
                    // on the outstanding read()/write() on the socket).
                    reasonName = displayReason(reason);
                    if (reasonName != null ) {
                        System.err.println("ERROR: "+reasonName+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!");
                    } else {
                        System.err.println("ERROR: Unknown/undefined reason "+reason+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!");
                    }
                    approval = false;
                }
            }

            return approval;
        }
    }

    private class JSSProtocolSocketFactory implements SchemeSocketFactory, LayeredSchemeSocketFactory {

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

            // Initialize JSS before using SSLSocket,
            // otherwise it will throw UnsatisfiedLinkError.
            if (config.getCertDatabase() == null) {
                try {
                    // No database specified, use $HOME/.pki/nssdb.
                    File homeDir = new File(System.getProperty("user.home"));
                    File pkiDir = new File(homeDir, ".pki");
                    File nssdbDir = new File(pkiDir, "nssdb");
                    nssdbDir.mkdirs();

                    CryptoManager.initialize(nssdbDir.getAbsolutePath());

                } catch (AlreadyInitializedException e) {
                    // ignore

                } catch (Exception e) {
                    throw new Error(e);
                }

            } else {
                // Database specified, already initialized by the main program.
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
                        new ServerCertApprovalCB(),
                        null);

            } else {
                socket = new SSLSocket(sock, hostName, new ServerCertApprovalCB(), null);
            }

            String certNickname = config.getCertNickname();
            if (certNickname != null) {
                if (verbose) System.out.println("Client certificate: "+certNickname);
                socket.setClientCertNickname(certNickname);
            }

            return socket;
        }

        @Override
        public boolean isSecure(Socket sock) {
            // We only use this factory in the case of SSL Connections.
            return true;
        }

        @Override
        public Socket createLayeredSocket(Socket socket, String target, int port, boolean autoClose)
                throws IOException, UnknownHostException {
            // This method implementation is required to get SSL working.
            return null;
        }

    }

    public <T> T createProxy(Class<T> clazz) throws URISyntaxException {
        URI uri = new URI(config.getServerURI()+"/rest");
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

    public ClientResponse<String> post(String content) throws Exception {
        ClientRequest request = executor.createRequest(config.getServerURI().toString());
        request.body(MediaType.APPLICATION_FORM_URLENCODED, content);
        return request.post(String.class);
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }
}
