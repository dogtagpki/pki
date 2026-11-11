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
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.ChainElement;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.client5.http.impl.LaxRedirectStrategy;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpResponseInterceptor;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ProtocolException;
import org.apache.hc.core5.http.io.entity.BufferedHttpEntity;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.message.RequestLine;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.dogtagpki.client.JSSSocketFactory;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.PKIException;

/**
 *
 */
public class PKIConnection implements AutoCloseable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIConnection.class);

    ClientConfig config;

    CloseableHttpClient httpClient;
    SSLCertificateApprovalCallback callback;
    LayeredConnectionSocketFactory socketFactory;

    URI target;

    int requestCounter;
    int responseCounter;

    File output;

    public PKIConnection(ClientConfig config) throws Exception {

        this.config = config;

        // create socket factory
        String className = System.getProperty(
                "org.dogtagpki.client.socketFactory",
                JSSSocketFactory.class.getName());
        logger.debug("PKIConnection: Creating connection with " + className);

        Class<? extends LayeredConnectionSocketFactory> clazz =
                Class.forName(className).asSubclass(LayeredConnectionSocketFactory.class);

        socketFactory = clazz.getConstructor(PKIConnection.class).newInstance(this);

        HttpClientBuilder httpClientBuilder = HttpClients.custom().setConnectionManager(
                PoolingHttpClientConnectionManagerBuilder.create()
                        .setSSLSocketFactory(socketFactory).build());

        // Don't retry operations.
        httpClientBuilder.disableAutomaticRetries();
        httpClientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                .setCookieSpec(StandardCookieSpec.RELAXED)
                .build());

        httpClientBuilder.addRequestInterceptorLast(new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, EntityDetails entity, HttpContext context)
                    throws HttpException, IOException {

                requestCounter++;

                logger.info("HTTP request: " + new RequestLine(request));
                for (Header header : request.getHeaders()) {
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
            }
        });

        httpClientBuilder.addResponseInterceptorLast(new HttpResponseInterceptor() {
            @Override
            public void process(HttpResponse response, EntityDetails entity, HttpContext context)
                    throws HttpException, IOException {

                responseCounter++;

                logger.info("HTTP response: " + new StatusLine(response));
                for (Header header : response.getHeaders()) {
                    logger.debug("- " + header.getName() + ": " + header.getValue());
                }

                if (output != null) {
                    File file = new File(output, "http-response-"+responseCounter);
                    try (PrintStream out = new PrintStream(file)) {
                        storeResponse(out, (ClassicHttpResponse) response);
                    }
                    logger.debug("Response: " + file.getAbsolutePath());

                } else if (logger.isDebugEnabled()) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    try (PrintStream out = new PrintStream(os)) {
                        storeResponse(out, (ClassicHttpResponse) response);
                    }
                    logger.debug("Response:\n" + os.toString("UTF-8"));
                }
            }
        });

        // Preserve the method and body when the server redirects a PKI operation.
        final String originalRequestKey = "org.dogtagpki.redirect.originalRequest";
        httpClientBuilder.addExecInterceptorBefore(
                ChainElement.REDIRECT.name(),
                "pki-original-request", (request, scope, chain) -> {
                    // Keep the headers before protocol processing adds credentials and framing.
                    scope.clientContext.setAttribute(originalRequestKey,
                            ClassicRequestBuilder.copy(request).build());
                    try {
                        return chain.proceed(request, scope);
                    } finally {
                        scope.clientContext.removeAttribute(originalRequestKey);
                    }
                });
        httpClientBuilder.setRedirectStrategy(new LaxRedirectStrategy() {
            @Override
            public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context) {
                if (response.getCode() == HttpStatus.SC_PERMANENT_REDIRECT) {
                    return response.containsHeader(HttpHeaders.LOCATION) && isRedirectable(request.getMethod());
                }
                return super.isRedirected(request, response, context);
            }

            @Override
            public boolean isRedirectAllowed(HttpHost current,
                    HttpHost target,
                    HttpRequest redirect, HttpContext context) {
                ClassicHttpRequest original = (ClassicHttpRequest) context.getAttribute(originalRequestKey);
                // LaxRedirectStrategy deliberately bypasses sensitive-header checks.
                return DefaultRedirectStrategy.INSTANCE
                        .isRedirectAllowed(current, target,
                                original == null ? redirect : original, context);
            }
        });
        httpClientBuilder.addExecInterceptorAfter(
                ChainElement.REDIRECT.name(),
                "pki-preserve-redirect-method", (request, scope, chain) -> {
                    ClassicHttpRequest original = (ClassicHttpRequest)
                            scope.clientContext.getAttribute(originalRequestKey);
                    if (original != null && !original.getMethod().equals(request.getMethod())) {
                        try {
                            request = ClassicRequestBuilder.copy(original).setUri(request.getUri()).build();
                        } catch (URISyntaxException e) {
                            throw new ProtocolException("Invalid redirect URI", e);
                        }
                    }
                    return chain.proceed(request, scope);
                });

        if (config.getUsername() != null && config.getPassword() != null) {
            URL url = config.getServerURL();
            BasicCredentialsProvider credsProvider = new BasicCredentialsProvider();
            logger.info("Set cred for: {} on {}", url.getHost(), url.getPort());
            credsProvider.setCredentials(
                    new AuthScope(url.getHost(), url.getPort()),
                    new UsernamePasswordCredentials(config.getUsername(), config.getPassword().toCharArray()));
            httpClientBuilder.setDefaultCredentialsProvider(credsProvider);
        }
        String messageFormat = config.getMessageFormat();
        if (messageFormat != null) {
            List<Header> headers = new ArrayList<>();

            if (messageFormat.equals("xml")) {
                headers.add(new BasicHeader(HttpHeaders.ACCEPT, MimeType.APPLICATION_XML));
            }
            if (messageFormat.equals("json")) {
                headers.add(new BasicHeader(HttpHeaders.ACCEPT, MimeType.APPLICATION_JSON));
            }
            httpClientBuilder.setDefaultHeaders(headers);
        }
        httpClient = httpClientBuilder.build();

        target = config.getServerURL().toURI();
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

    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }

    public void storeRequest(PrintStream out, HttpRequest request) throws IOException {
        if (request instanceof ClassicHttpRequest enclose) {
            HttpEntity entity = enclose.getEntity();
            if (entity == null) return;

            if (!entity.isRepeatable()) {
                BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
                enclose.setEntity(bufferedEntity);
                entity = bufferedEntity;
            }

            storeEntity(out, entity);
        }
    }

    public void storeResponse(PrintStream out, ClassicHttpResponse response) throws IOException {
        HttpEntity entity = response.getEntity();
        if (entity == null) return;

        if (!entity.isRepeatable()) {
            BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
            response.setEntity(bufferedEntity);
            entity = bufferedEntity;
        }
        storeEntity(out, entity);
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

    public URI getTarget() {
        return target;
    }

    public File getOutput() {
        return output;
    }

    public void setOutput(File output) {
        this.output = output;
    }

    @Override
    public void close() {
        try {
            httpClient.close();
        } catch (IOException e) {
            logger.error("PKIConnection: cannot close httpClient - {}", e.getMessage());
            throw new PKIException(e);
        }
    }
}
