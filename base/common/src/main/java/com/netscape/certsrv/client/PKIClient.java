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
import java.util.Arrays;
import java.util.Map;

import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status.Family;
import javax.ws.rs.core.Response.StatusType;

import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoClient;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.base.PKIException;


public class PKIClient implements AutoCloseable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIClient.class);

    public final static String[] MESSAGE_FORMATS = { "json", "xml" };

    public ClientConfig config;
    public PKIConnection connection;
    public String apiVersion;
    public MediaType messageFormat;
    public InfoClient infoClient;
    public Info info;

    public PKIClient(ClientConfig config) throws Exception {
        this(config, null);
    }

    public PKIClient(ClientConfig config, SSLCertificateApprovalCallback callback) throws Exception {
        this(config, "rest", callback);
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

        this.messageFormat = MediaType.valueOf("application/" + messageFormat);
    }

    public String getAPIVersion() {
        return apiVersion;
    }

    public MediaType getMessageFormat() {
        return messageFormat;
    }

    public String getSubsystem() {
        return config.getSubsystem();
    }

    /**
    * Marshall request object with custom mapping if available.
    */
   public Object marshall(Object request) throws Exception {

       Class<?> clazz = request.getClass();

       try {
           if (MediaType.APPLICATION_XML_TYPE.isCompatible(messageFormat)) {
               Method method = clazz.getMethod("toXML");
               request = method.invoke(request);

           } else if (MediaType.APPLICATION_JSON_TYPE.isCompatible(messageFormat)) {
               Method method = clazz.getMethod("toJSON");
               request = method.invoke(request);

           } else {
               throw new Exception("Unsupported request format: " + messageFormat);
           }

       } catch (NoSuchMethodException e) {
           logger.info("PKIClient: " + clazz.getSimpleName() + " has no custom mapping for " + messageFormat);

       } catch (Exception e) {
           logger.error("PKIClient: Unable to marshall request: " + e.getMessage(), e);
           throw e;
       }

       return request;
   }

    /**
     * Unmarshall response object using custom mapping if available.
     */
    public <T> T unmarshall(Response response, Class<T> clazz) throws Exception {

        MediaType responseFormat = response.getMediaType();

        try {
            if (MediaType.APPLICATION_XML_TYPE.isCompatible(responseFormat)) {
                Method method = clazz.getMethod("fromXML", String.class);
                String xml = response.readEntity(String.class);
                return (T) method.invoke(null, xml);

            } else if (MediaType.APPLICATION_JSON_TYPE.isCompatible(responseFormat)) {
                // TODO: support custom JSON mapping
                // Method method = clazz.getMethod("fromJSON", String.class);
                // String json = response.readEntity(String.class);
                // return (T) method.invoke(null, json);
            }

        } catch (NoSuchMethodException e) {
            logger.info("PKIClient: " + clazz.getSimpleName() + " has no custom mapping for " + responseFormat);

        } catch (Exception e) {
            logger.error("PKIClient: Unable to unmarshall response: " + e.getMessage(), e);
            throw e;
        }

        return response.readEntity(clazz);
    }

    public void handleErrorResponse(Response response) throws Exception {

        MediaType contentType = response.getMediaType();

        if (!MediaType.APPLICATION_XML_TYPE.isCompatible(contentType)
                && !MediaType.APPLICATION_JSON_TYPE.isCompatible(contentType)) {

            StatusType status = response.getStatusInfo();
            throw new PKIException(status.getStatusCode(), status.getReasonPhrase());
        }

        PKIException.Data data = unmarshall(response, PKIException.Data.class);
        String className = data.getClassName();

        Class<? extends PKIException> exceptionClass =
                Class.forName(className).asSubclass(PKIException.class);

        Constructor<? extends PKIException> constructor =
                exceptionClass.getConstructor(PKIException.Data.class);

        throw constructor.newInstance(data);
    }

    public <T> Entity<T> entity(T object) throws Exception {
        return Entity.entity(object, messageFormat);
    }

    public <T> T getEntity(Response response, Class<T> clazz) throws Exception {
        try {
            Family family = response.getStatusInfo().getFamily();

            if (family.equals(Family.CLIENT_ERROR) || family.equals(Family.SERVER_ERROR)) {
                handleErrorResponse(response);
                return null;
            }

            if (!response.hasEntity()) {
                return null;
            }

            return unmarshall(response, clazz);

        } finally {
            response.close();
        }
    }

    public <T> T getEntity(Response response, GenericType<T> clazz) throws Exception {
        try {
            Family family = response.getStatusInfo().getFamily();

            if (family.equals(Family.CLIENT_ERROR) || family.equals(Family.SERVER_ERROR)) {
                handleErrorResponse(response);
                return null;
            }

            if (!response.hasEntity()) {
                return null;
            }

            return response.readEntity(clazz);

        } finally {
            response.close();
        }
    }

    public ClientConfig getConfig() {
        return config;
    }

    public PKIConnection getConnection() {
        return connection;
    }

    public WebTarget target(String path, Map<String, Object> params) {
        WebTarget target = connection.target(path);
        if (params != null) {
            for (String name : params.keySet()) {
                Object value = params.get(name);
                if (value == null) continue;
                target = target.queryParam(name, value);
            }
        }
        return target;
    }

    public <T> T get(String path, Class<T> responseType) throws Exception {
        return get(path, null, responseType);
    }

    public <T> T get(String path, Map<String, Object> params, Class<T> responseType) throws Exception {
        WebTarget target = target(path, params);
        Response response = target.request().get();
        return getEntity(response, responseType);
    }

    public <T> T get(String path, Map<String, Object> params, GenericType<T> responseType) throws Exception {
        WebTarget target = target(path, params);
        Response response = target.request().get();
        return getEntity(response, responseType);
    }

    public <T> T post(String path, Class<T> responseType) throws Exception {
        return post(path, (Map<String, Object>) null, responseType);
    }

    public <T> T post(String path, Map<String, Object> params, Class<T> responseType) throws Exception {
        return post(path, params, null, responseType);
    }

    public <T> T post(String path, Map<String, Object> params, Entity<?> entity, Class<T> responseType) throws Exception {
        WebTarget target = target(path, params);
        Response response = target.request().post(entity);
        return getEntity(response, responseType);
    }

    public <T> T post(String path, MultivaluedMap<String, String> content, Class<T> responseType) throws Exception {
        WebTarget target = connection.target(path);
        Response response = target.request().post(Entity.form(content));
        return getEntity(response, responseType);
    }

    public <T> T put(String path, Map<String, Object> params, Entity<?> entity, Class<T> responseType) throws Exception {
        WebTarget target = target(path, params);
        Response response = target.request().put(entity);
        return getEntity(response, responseType);
    }

    public <T> T patch(String path, Map<String, Object> params, Entity<?> entity, Class<T> responseType) throws Exception {
        WebTarget target = target(path, params);
        Response response = target.request().method("PATCH", entity);
        return getEntity(response, responseType);
    }

    public <T> T delete(String path, Class<T> responseType) throws Exception {
        Response response = connection.target(path).request().delete();
        return getEntity(response, responseType);
    }

    public <T> T delete(String path, Map<String, Object> params, Class<T> responseType) throws Exception {
        WebTarget target = target(path, params);
        Response response = target.request().delete();
        return getEntity(response, responseType);
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
