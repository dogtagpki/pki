package com.netscape.certsrv.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status.Family;
import javax.ws.rs.core.Response.StatusType;

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
import org.jboss.resteasy.client.jaxrs.ProxyBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLSocket;

import com.netscape.certsrv.base.PKIException;


public class PKIConnection {

    PKIClient client;
    ClientConfig config;

    Collection<Integer> rejectedCertStatuses = new HashSet<Integer>();
    Collection<Integer> ignoredCertStatuses = new HashSet<Integer>();

    // List to prevent displaying the same warnings/errors again.
    Collection<Integer> statuses = new HashSet<Integer>();

    DefaultHttpClient httpClient = new DefaultHttpClient();

    ApacheHttpClient4Engine engine;
    ResteasyClient resteasyClient;
    ResteasyProviderFactory providerFactory;

    int requestCounter;
    int responseCounter;

    File output;

    public PKIConnection(final PKIClient client) {

        this.client = client;

        config = client.getConfig();

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

                if (client.verbose) {
                    System.out.println("HTTP request: "+request.getRequestLine());
                    for (Header header : request.getAllHeaders()) {
                        System.out.println("  "+header.getName()+": "+header.getValue());
                    }
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

                if (client.verbose) {
                    System.out.println("HTTP response: "+response.getStatusLine());
                    for (Header header : response.getAllHeaders()) {
                        System.out.println("  "+header.getName()+": "+header.getValue());
                    }
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
                if (client.verbose) System.out.println("HTTP redirect: "+uri);

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
        resteasyClient = new ResteasyClientBuilder().httpEngine(engine).build();
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

        public String getMessage(X509Certificate serverCert, int reason) {

            if (reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {

                return "BAD_CERT_DOMAIN encountered on '"+serverCert.getSubjectDN()+"' indicates a common-name mismatch";
            }

            if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER) {
                return "UNTRUSTED ISSUER encountered on '" +
                        serverCert.getSubjectDN() + "' indicates a non-trusted CA cert '" +
                        serverCert.getIssuerDN() + "'";
            }

            if (reason == SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID) {
                return "CA_CERT_INVALID encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
            }

            String reasonName = displayReason(reason);
            if (reasonName != null) {
                return reasonName+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
            }

            return "Unknown/undefined reason "+reason+" encountered on '"+serverCert.getSubjectDN()+"' results in a denied SSL server cert!";
        }

        public boolean handleUntrustedIssuer(X509Certificate serverCert) {
            try {
                System.out.print("Import CA certificate (Y/n)? ");

                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                String line = reader.readLine().trim();

                if (!line.equals("") && !line.equalsIgnoreCase("Y"))
                    return false;

                String caServerURI = "http://" + config.getServerURI().getHost() + ":8080/ca";

                System.out.print("CA server URI [" + caServerURI + "]: ");
                System.out.flush();

                line = reader.readLine().trim();
                if (!line.equals("")) {
                    caServerURI = line;
                }

                if (client.verbose) System.out.println("Downloading CA certificate chain from " + caServerURI + ".");
                byte[] bytes = client.downloadCACertChain(caServerURI);

                if (client.verbose) System.out.println("Importing CA certificate chain.");
                client.importCACertPackage(bytes);

                if (client.verbose) System.out.println("Imported CA certificate.");
                return true;

            } catch (Exception e) {
                System.err.println("ERROR: "+e);
                return false;
            }
        }

        // Callback to approve or deny returned SSL server cert.
        // Right now, simply approve the cert.
        public boolean approve(X509Certificate serverCert,
                SSLCertificateApprovalCallback.ValidityStatus status) {

            boolean approval = true;

            if (client.verbose) System.out.println("Server certificate: "+serverCert.getSubjectDN());

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

                if (isRejected(reason)) {
                    if (!statuses.contains(reason))
                        System.err.println("ERROR: " + getMessage(serverCert, reason));
                    approval = false;

                } else if (isIgnored(reason)) {
                    // Ignore validity status

                } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.UNTRUSTED_ISSUER) {
                    // Issue a WARNING, but allow this process
                    // to continue since we haven't installed a trusted CA
                    // cert for this operation.
                    if (!statuses.contains(reason)) {
                        System.err.println("WARNING: " + getMessage(serverCert, reason));
                        handleUntrustedIssuer(serverCert);
                    }

                } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.BAD_CERT_DOMAIN) {
                    // Issue a WARNING, but allow this process to continue on
                    // common-name mismatches.
                    if (!statuses.contains(reason))
                        System.err.println("WARNING: " + getMessage(serverCert, reason));

                } else if (reason == SSLCertificateApprovalCallback.ValidityStatus.CA_CERT_INVALID) {
                    // Set approval false to deny this
                    // certificate so that the connection is terminated.
                    // (Expect an IOException on the outstanding
                    //  read()/write() on the socket).
                    if (!statuses.contains(reason))
                        System.err.println("ERROR: " + getMessage(serverCert, reason));
                    approval = false;

                } else {
                    // Set approval false to deny this certificate so that
                    // the connection is terminated. (Expect an IOException
                    // on the outstanding read()/write() on the socket).
                    if (!statuses.contains(reason))
                        System.err.println("ERROR: " + getMessage(serverCert, reason));
                    approval = false;
                }

                statuses.add(reason);
            }

            return approval;
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

            org.mozilla.jss.ssl.SSLSocket.SSLVersionRange stream_range =
                new org.mozilla.jss.ssl.SSLSocket.SSLVersionRange(
                    org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_0,
                    org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_2);

            SSLSocket.setSSLVersionRangeDefault(
                    org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.STREAM,
                    stream_range);

            org.mozilla.jss.ssl.SSLSocket.SSLVersionRange datagram_range =
                new org.mozilla.jss.ssl.SSLSocket.SSLVersionRange(
                    org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_1,
                    org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_2);

            SSLSocket.setSSLVersionRangeDefault(
                    org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.DATA_GRAM,
                    datagram_range);
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
// setSSLVersionRange needs to be exposed in jss
//            socket.setSSLVersionRange(org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_0, org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_2);

            String certNickname = config.getCertNickname();
            if (certNickname != null) {
                if (client.verbose) System.out.println("Client certificate: "+certNickname);
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
        public Socket createLayeredSocket(Socket socket, String target, int port, HttpParams params)
                throws IOException, UnknownHostException {
            // This method implementation is required to get SSL working.
            return null;
        }

    }

    public <T> T createProxy(URI uri, Class<T> clazz) throws URISyntaxException {
        ResteasyWebTarget target = resteasyClient.target(uri);
        ProxyBuilder<T> builder = ProxyBuilder.builder(clazz, target);

        String messageFormat = config.getMessageFormat();
        if (messageFormat == null) messageFormat = PKIClient.MESSAGE_FORMATS[0];

        if (!Arrays.asList(PKIClient.MESSAGE_FORMATS).contains(messageFormat)) {
            throw new Error("Unsupported message format: " + messageFormat);
        }

        MediaType contentType = MediaType.valueOf("application/" + messageFormat);
        builder.defaultConsumes(contentType);
        builder.defaultProduces(contentType);

        return builder.build();
    }

    public <T> T getEntity(Response response, Class<T> clazz) {

        // handle HTTP status code 4xx and 5xx only
        StatusType status = response.getStatusInfo();
        Family family = status.getFamily();
        if (!family.equals(Family.CLIENT_ERROR) && !family.equals(Family.SERVER_ERROR)) {
            if (response.hasEntity()) return response.readEntity(clazz);
            return null;
        }

        MediaType contentType = response.getMediaType();

        if (!MediaType.APPLICATION_XML_TYPE.equals(contentType)
                && !MediaType.APPLICATION_JSON_TYPE.equals(contentType))
            throw new PKIException(status.getStatusCode(), status.getReasonPhrase());

        PKIException.Data data = response.readEntity(PKIException.Data.class);

        Class<?> exceptionClass;
        try {
            exceptionClass = Class.forName(data.getClassName());
        } catch (ClassNotFoundException e) {
            throw new PKIException(e.getMessage(), e);
        }

        try {
            throw (PKIException) exceptionClass.getConstructor(PKIException.Data.class).newInstance(data);
        } catch (InstantiationException
                | IllegalAccessException
                | IllegalArgumentException
                | InvocationTargetException
                | NoSuchMethodException
                | SecurityException e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    public String post(MultivaluedMap<String, String> form) throws Exception {
        ResteasyWebTarget target = resteasyClient.target(config.getServerURI());
        return target.request().post(Entity.form(form), String.class);
    }

    public void addRejectedCertStatus(Integer rejectedCertStatus) {
        rejectedCertStatuses.add(rejectedCertStatus);
    }

    public void setRejectedCertStatuses(Collection<Integer> rejectedCertStatuses) {
        this.rejectedCertStatuses.clear();
        if (rejectedCertStatuses == null) return;
        this.rejectedCertStatuses.addAll(rejectedCertStatuses);
    }

    public boolean isRejected(Integer certStatus) {
        return rejectedCertStatuses.contains(certStatus);
    }

    public void addIgnoredCertStatus(Integer ignoredCertStatus) {
        ignoredCertStatuses.add(ignoredCertStatus);
    }

    public void setIgnoredCertStatuses(Collection<Integer> ignoredCertStatuses) {
        this.ignoredCertStatuses.clear();
        if (ignoredCertStatuses == null) return;
        this.ignoredCertStatuses.addAll(ignoredCertStatuses);
    }

    public boolean isIgnored(Integer certStatus) {
        return ignoredCertStatuses.contains(certStatus);
    }

    public File getOutput() {
        return output;
    }

    public void setOutput(File output) {
        this.output = output;
    }
}
