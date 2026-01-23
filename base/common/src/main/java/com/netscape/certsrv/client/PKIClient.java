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
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoClient;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.ClientConnectionException;
import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.util.JSONSerializer;


public class PKIClient implements AutoCloseable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIClient.class);

    public final static String[] MESSAGE_FORMATS = { "json", "xml" };

    public ClientConfig config;
    public PKIConnection connection;
    public String apiVersion;
    public InfoClient infoClient;
    public Info info;
    public URI basicURI;
    private String defaultMimeType;

    public PKIClient(ClientConfig config) throws Exception {
        this(config, null);
    }

    public PKIClient(ClientConfig config, SSLCertificateApprovalCallback callback) throws Exception {
        this(config, "v2", callback);
    }

    public PKIClient(ClientConfig config, String apiVersion, SSLCertificateApprovalCallback callback) throws Exception {
        this.config = config;
        this.apiVersion = apiVersion;

        connection = new PKIConnection(config);
        connection.setCallback(callback);

        String messageFormat = config.getMessageFormat();
        if (messageFormat == null) messageFormat = MESSAGE_FORMATS[0];

        if (!Arrays.asList(MESSAGE_FORMATS).contains(messageFormat)) {
            throw new Error("Unsupported message format: " + messageFormat);
        }

        this.defaultMimeType = "application/" + messageFormat;
    }

    public String getAPIVersion() {
        return apiVersion;
    }

    public String getDefaultMimeType() {
        return defaultMimeType;
    }

    public String getSubsystem() {
        return config.getSubsystem();
    }

    /**
    * Marshall request object with custom mapping if available.
    */
   public String marshall(Object request) throws Exception {

       Class<?> clazz = request.getClass();
       Object result = null;
       try {
           if (MimeType.APPLICATION_XML.equals(defaultMimeType)) {
               Method method = clazz.getMethod("toXML");
               result = method.invoke(request);

           } else if (MimeType.APPLICATION_JSON.equals(defaultMimeType)) {
               Method method = clazz.getMethod("toJSON");
               result = method.invoke(request);

           } else {
               throw new Exception("Unsupported request format: " + defaultMimeType);
           }

       } catch (NoSuchMethodException e) {
           logger.info("PKIClient: " + clazz.getSimpleName() + " has no custom mapping for " + defaultMimeType);

       } catch (Exception e) {
           logger.error("PKIClient: Unable to marshall request: " + e.getMessage(), e);
           throw e;
       }

       if (result instanceof String res) {
           return res;
       }
       return null;
   }

    /**
     * Unmarshall response object using custom mapping if available.
     */
    public <T> T unmarshall(HttpEntity entity, Class<T> clazz) throws Exception {

        if (entity == null) {
            return null;
        }

        String response = EntityUtils.toString(entity, StandardCharsets.UTF_8);
        if (response == null || response.isBlank()) {
            return null;
        }

        if (clazz.isInstance(response)) {
            return clazz.cast(response);
        }
        if (clazz.isInstance(response.getBytes())) {
            return clazz.cast(response.getBytes());
        }

        String contentType = null;
        if (entity.getContentType() != null) {
            contentType = entity.getContentType().getValue().split(";")[0].trim();
        }
        try {
            if (MimeType.APPLICATION_XML.equals(contentType)) {
                Method method = clazz.getMethod("fromXML", String.class);
                return (T) method.invoke(null, response);
            }

            if (MimeType.APPLICATION_JSON.equals(contentType)) {
                return JSONSerializer.fromJSON(response, clazz);
            }
        } catch (NoSuchMethodException e) {
            logger.info("PKIClient: " + clazz.getSimpleName() + " has no custom mapping for " + entity.getContentType());

        } catch (Exception e) {
            logger.error("PKIClient: Unable to unmarshall response: " + e.getMessage(), e);
            throw e;
        }
        return null;
    }

    public <T> Collection<T> unmarshallCollection(HttpEntity entity, Class<T> clazz) throws Exception {

        if (entity == null) {
            return null;
        }

        String response = EntityUtils.toString(entity);

        String contentType = null;
        if (entity.getContentType() != null) {
            contentType = entity.getContentType().getValue().split(";")[0].trim();
        }
        try {
            if (MimeType.APPLICATION_XML.equals(contentType)) {
                //TODO: Add the mapping after fix XML generation  on server side
//                Method method = clazz.getMethod("fromXML", String.class);
//                return (T) method.invoke(null, response);
            }

            if (MimeType.APPLICATION_JSON.equals(contentType)) {
                ObjectMapper mapper = new ObjectMapper();
                return mapper.readValue(response, mapper.getTypeFactory().constructCollectionType(ArrayList.class, clazz));
            }
//        } catch (NoSuchMethodException e) {
//            logger.info("PKIClient: " + collectClazz.getSimpleName() + " has no custom mapping for " + entity.getContentType());
        } catch (Exception e) {
            logger.error("PKIClient: Unable to unmarshall response: " + e.getMessage(), e);
            throw e;
        }

        return null;
    }

    public void handleErrorResponse(CloseableHttpResponse httpResp) throws Exception {
        HttpEntity entity = httpResp.getEntity();
        String contentType = null;
        if (entity != null && entity.getContentType() != null) {
            contentType = entity.getContentType().getValue().split(";")[0].trim();
        }

        if (entity == null ||
                (!MimeType.APPLICATION_XML.equals(contentType) &&
                        !MimeType.APPLICATION_JSON.equals(contentType))) {

            StatusLine status = httpResp.getStatusLine();
            switch (status.getStatusCode()) {
            case HttpStatus.SC_UNAUTHORIZED:
                throw new UnauthorizedException(status.getReasonPhrase());
            case HttpStatus.SC_NOT_FOUND:
                throw new ResourceNotFoundException(status.getReasonPhrase());
            default:
                throw new PKIException(status.getStatusCode(), status.getReasonPhrase());
            }
        }

        PKIException.Data data = unmarshall(entity, PKIException.Data.class);
        String className = data.getClassName();

        Class<? extends PKIException> exceptionClass =
                Class.forName(className).asSubclass(PKIException.class);

        Constructor<? extends PKIException> constructor =
                exceptionClass.getConstructor(PKIException.Data.class);

        throw constructor.newInstance(data);
    }

    public <T> HttpEntity entity(T object) throws Exception {
        if (object instanceof byte[] raw) {
            return EntityBuilder.create()
                    .setBinary(raw)
                    .build();
        }

        if (object instanceof String text) {
            //TODO: This is not a json/xml object but v1 API mapping is not working if set to text
            //      Can be removed when v1 APIs dropped
            return EntityBuilder.create()
                    .setContentType(ContentType.create(defaultMimeType))
                    .setText(text)
                    .build();
        }

        byte[] bytes = marshall(object).getBytes(StandardCharsets.UTF_8);

        return EntityBuilder.create()
                .setContentType(ContentType.create(defaultMimeType))
                .setBinary(bytes)
                .build();
    }

    public <T> T getEntity(CloseableHttpResponse httpResp, Class<T> clazz) throws Exception {
        try {
            int status = httpResp.getStatusLine().getStatusCode();
            if (status >= HttpStatus.SC_BAD_REQUEST) {
                handleErrorResponse(httpResp);
                return null;
            }

            return unmarshall(httpResp.getEntity(), clazz);

        } finally {
            httpResp.close();
        }
    }

    public <T> Collection<T> getEntities(CloseableHttpResponse  httpResp, Class<T> clazz) throws Exception {
        try {
            int status = httpResp.getStatusLine().getStatusCode();
            if (status >= HttpStatus.SC_BAD_REQUEST) {
                handleErrorResponse(httpResp);
                return null;
            }
            return unmarshallCollection(httpResp.getEntity(), clazz);
        } finally {
            httpResp.close();
        }
    }

    public ClientConfig getConfig() {
        return config;
    }

    public PKIConnection getConnection() {
        return connection;
    }

    public URIBuilder target(String path, Map<String, Object> params) {
        URIBuilder uriBuilder = new URIBuilder(connection.getTarget());
        if (path != null) {
            String fullPath;
            String uriPath = uriBuilder.getPath();
            if (uriPath == null || uriPath.isBlank()) {
                fullPath = path;
            } else {
                if (uriPath.endsWith("/") && path.startsWith("/")) {
                    fullPath = uriPath + path.substring(1);
                } else if (uriPath.endsWith("/") || path.startsWith("/")) {
                    fullPath = uriPath + path;
                } else {
                    fullPath = uriPath + "/" + path;
                }
            }
            uriBuilder.setPath(fullPath);
        }
        if (params != null) {
            for (String name : params.keySet()) {
                Object value = params.get(name);
                if (value == null) continue;
                uriBuilder.addParameter(name, value.toString());
            }
        }
        return uriBuilder;
    }

    public <T> T get(String path, Class<T> responseType) throws Exception {
        return get(path, null, responseType);
    }

    public <T> T get(String path, Map<String, Object> params, Class<T> responseType) throws Exception {
        URIBuilder target = target(path, params);
        HttpGet httpGET = new HttpGet(target.build());
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = connection.getHttpClient().execute(httpGET);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return getEntity(httpResp, responseType);
    }

    public <T> Collection<T> getCollection(String path, Map<String, Object> params, Class<T> responseType) throws Exception {
        URIBuilder target = target(path, params);
        HttpGet httpGET = new HttpGet(target.build());
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = connection.getHttpClient().execute(httpGET);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return getEntities(httpResp, responseType);
    }

    public <T> T post(String path, Class<T> responseType) throws Exception {
        return post(path, (Map<String, Object>) null, responseType);
    }

    public <T> T post(String path, Map<String, Object> params, Class<T> responseType) throws Exception {
        return post(path, params, null, responseType);
    }

    public <T> T post(String path, Map<String, Object> params, HttpEntity entity, Class<T> responseType) throws Exception {
        URIBuilder target = target(path, params);
        HttpPost httpPOST = new HttpPost(target.build());
        if (entity != null) {
            httpPOST.setEntity(entity);
        }
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = connection.getHttpClient().execute(httpPOST);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return getEntity(httpResp, responseType);
    }

    public <T> T post(String path, List<NameValuePair> content, Class<T> responseType) throws Exception {
        URIBuilder target = target(path, null);
        UrlEncodedFormEntity entity = new UrlEncodedFormEntity(content, Consts.UTF_8);
        HttpPost httpPOST = new HttpPost(target.build());
        httpPOST.setEntity(entity);
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = connection.getHttpClient().execute(httpPOST);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return getEntity(httpResp, responseType);
    }

    public <T> T put(String path, Map<String, Object> params, HttpEntity entity, Class<T> responseType) throws Exception {
        URIBuilder target = target(path, params);
        HttpPut httpPUT = new HttpPut(target.build());
        if (entity != null) {
            httpPUT.setEntity(entity);
        }
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = connection.getHttpClient().execute(httpPUT);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return getEntity(httpResp, responseType);
    }

    public <T> T patch(String path, Map<String, Object> params, HttpEntity entity, Class<T> responseType) throws Exception {
        URIBuilder target = target(path, params);
        HttpPatch httpPATCH = new HttpPatch(target.build());
        if (entity != null) {
            httpPATCH.setEntity(entity);
        }
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = connection.getHttpClient().execute(httpPATCH);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return getEntity(httpResp, responseType);
    }

    public <T> T delete(String path, Class<T> responseType) throws Exception {
        return delete(path, null, responseType);
    }

    public <T> T delete(String path, Map<String, Object> params, Class<T> responseType) throws Exception {
        URIBuilder target = target(path, params);
        HttpDelete httpDELETE = new HttpDelete(target.build());
        CloseableHttpResponse httpResp = null;
        try {
            httpResp = connection.getHttpClient().execute(httpDELETE);
        } catch (Exception ex) {
            throw new ClientConnectionException(ex);
        }
        return getEntity(httpResp, responseType);

    }

    public Info getInfo() throws Exception {
        if (infoClient == null) {
            infoClient = new InfoClient(this);
            info = infoClient.getInfo();
        }
        return info;
    }

    public void setOutput(File output) {
        connection.setOutput(output);
    }

    @Override
    public void close() {
        connection.close();
    }
}
