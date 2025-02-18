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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;

import javax.ws.rs.Priorities;
import javax.ws.rs.client.WebTarget;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.ProtocolException;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeLayeredSocketFactory;
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
import org.dogtagpki.client.JSSSocketFactory;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

public class PKIConnection implements AutoCloseable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIConnection.class);

    ClientConfig config;

    DefaultHttpClient httpClient = new DefaultHttpClient();
    SSLCertificateApprovalCallback callback;
    SchemeLayeredSocketFactory socketFactory;

    ApacheHttpClient4Engine engine;
    javax.ws.rs.client.Client client;
    WebTarget target;

    int requestCounter;
    int responseCounter;

    File output;

    public PKIConnection(ClientConfig config) throws Exception {

        this.config = config;

        // create socket factory
        String className = System.getProperty(
                "org.dogtagpki.client.socketFactory",
                JSSSocketFactory.class.getName());
        logger.info("PKIConnection: Socket factory: " + className);

        Class<? extends SchemeLayeredSocketFactory> clazz =
                Class.forName(className).asSubclass(SchemeLayeredSocketFactory.class);

        socketFactory = clazz.getConstructor(PKIConnection.class).newInstance(this);

        // Register https scheme.
        Scheme scheme = new Scheme("https", 443, socketFactory);

        httpClient.getConnectionManager().getSchemeRegistry().register(scheme);

        // Don't retry operations.
        httpClient.setHttpRequestRetryHandler(new DefaultHttpRequestRetryHandler(0, false));

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

                    logger.debug("- " + name + ": " + value);
                }

                if (output != null) {
                    File file = new File(output, "http-request-"+requestCounter);
                    try (PrintStream out = new PrintStream(file)) {
                        storeRequest(out, request);
                    }
                    logger.debug("Request: " + file.getAbsolutePath());

                } else if (logger.isDebugEnabled()) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    try (PrintStream out = new PrintStream(os)) {
                        storeRequest(out, request);
                    }
                    logger.debug("Request:\n" + os.toString("UTF-8"));
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
                    logger.debug("- " + header.getName() + ": " + header.getValue());
                }

                if (output != null) {
                    File file = new File(output, "http-response-"+responseCounter);
                    try (PrintStream out = new PrintStream(file)) {
                        storeResponse(out, response);
                    }
                    logger.debug("Response: " + file.getAbsolutePath());

                } else if (logger.isDebugEnabled()) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    try (PrintStream out = new PrintStream(os)) {
                        storeResponse(out, response);
                    }
                    logger.debug("Response:\n" + os.toString("UTF-8"));
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

        client.register(new PKIClientAuthenticator(config), Priorities.AUTHENTICATION);
        client.register(PKIRESTProvider.class);

        URI uri = config.getServerURL().toURI();
        target = client.target(uri);
    }

    public ClientConfig getConfig() {
        return config;
    }

    public SSLCertificateApprovalCallback getCallback() {
        return callback;
    }

    public void setCallback(SSLCertificateApprovalCallback callback) {
        this.callback = callback;
    }

    public void storeRequest(PrintStream out, HttpRequest request) throws IOException {

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

    public void storeResponse(PrintStream out, HttpResponse response) throws IOException {

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

    public void storeEntity(OutputStream out, HttpEntity entity) throws IOException {

        byte[] buffer = new byte[1024];
        int c;

        try (InputStream in = entity.getContent()) {
            while ((c = in.read(buffer)) > 0) {
                out.write(buffer, 0, c);
            }
        }
    }

    public WebTarget target(String path) {
        return target.path(path);
    }

    public File getOutput() {
        return output;
    }

    public void setOutput(File output) {
        this.output = output;
    }

    @Override
    public void close() {
        client.close();
        engine.close();
        httpClient.close();
    }
}
