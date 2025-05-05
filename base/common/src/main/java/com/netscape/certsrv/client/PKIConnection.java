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
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.ProtocolException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HttpContext;
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
        logger.info("PKIConnection: Socket factory: " + className);

        Class<? extends LayeredConnectionSocketFactory> clazz =
                Class.forName(className).asSubclass(LayeredConnectionSocketFactory.class);

        socketFactory = clazz.getConstructor(PKIConnection.class).newInstance(this);

        HttpClientBuilder httpClientBuilder = HttpClients.custom().setSSLSocketFactory(socketFactory);

        // Don't retry operations.
        httpClientBuilder.setRetryHandler(new DefaultHttpRequestRetryHandler(0, false));


        httpClientBuilder.addInterceptorLast(new HttpRequestInterceptor() {
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

                if (context instanceof HttpClientContext clientContext) {
                    RequestConfig reqConfig = RequestConfig.copy(clientContext.getRequestConfig())
                            .setRedirectsEnabled(true)
                            .setRelativeRedirectsAllowed(true)
                            .build();
                    clientContext.setRequestConfig(reqConfig);
                }
            }
        });

        httpClientBuilder.addInterceptorLast(new HttpResponseInterceptor() {
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

        // Default redirect strategy will convert POST method to GET if  the status code is 302
        // making the CLI failings in same cases. Therefore the policy is modified to keep the
        // same HTTP method used in the original request.
        // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/302
        httpClientBuilder.setRedirectStrategy(new LaxRedirectStrategy() {
            @Override
            public HttpUriRequest getRedirect(
                    final HttpRequest request,
                    final HttpResponse response,
                    final HttpContext context) throws ProtocolException {
                final URI uri = getLocationURI(request, response, context);
                return RequestBuilder.copy(request).setUri(uri).build();
            }
        });

        if (config.getUsername() != null && config.getPassword() != null) {
            URL url = config.getServerURL();
            CredentialsProvider credsProvider = new BasicCredentialsProvider();
            logger.info("Set cred for: {} on {}", url.getHost(), url.getPort());
            credsProvider.setCredentials(
                    new AuthScope(url.getHost(), url.getPort()),
                    new UsernamePasswordCredentials(config.getUsername(), config.getPassword()));
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
        if (request instanceof HttpEntityEnclosingRequest enclose) {
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

    public void storeResponse(PrintStream out, HttpResponse response) throws IOException {
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
