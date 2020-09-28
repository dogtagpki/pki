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
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

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
import org.jboss.resteasy.client.jaxrs.ProxyBuilder;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.util.CryptoProvider;


public class PKIClient {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIClient.class);

    public final static String[] MESSAGE_FORMATS = { "xml", "json" };

    public ClientConfig config;
    public PKIConnection connection;
    public CryptoProvider crypto;
    public InfoClient infoClient;
    public Info info;

    Collection<Integer> rejectedCertStatuses = new HashSet<Integer>();
    Collection<Integer> ignoredCertStatuses = new HashSet<Integer>();

    // List to prevent displaying the same warnings/errors again.
    Collection<Integer> statuses = new HashSet<Integer>();

    public PKIClient(ClientConfig config) throws URISyntaxException {
        this(config, null, null);
    }

    public PKIClient(ClientConfig config, CryptoProvider crypto) throws URISyntaxException {
        this(config, crypto, null);
    }

    public PKIClient(ClientConfig config, CryptoProvider crypto, SSLCertificateApprovalCallback callback) throws URISyntaxException {
        this.config = config;
        this.crypto = crypto;

        connection = new PKIConnection(config);

        if (callback == null) {
            callback = new PKICertificateApprovalCallback(this);
        }

        connection.setCallback(callback);
    }

    public <T> T createProxy(String path, Class<T> clazz) throws Exception {
        WebTarget target = connection.target(path);
        ProxyBuilder<T> builder = ProxyBuilder.builder(clazz, target);

        String messageFormat = config.getMessageFormat();
        if (messageFormat == null) messageFormat = MESSAGE_FORMATS[0];

        if (!Arrays.asList(MESSAGE_FORMATS).contains(messageFormat)) {
            throw new Error("Unsupported message format: " + messageFormat);
        }

        MediaType contentType = MediaType.valueOf("application/" + messageFormat);
        builder.defaultConsumes(contentType);
        builder.defaultProduces(contentType);

        return builder.build();
    }

    public String getSubsystem() {
        return config.getSubsystem();
    }

    public void handleErrorResponse(Response response) throws Exception {

        StatusType status = response.getStatusInfo();
        MediaType contentType = response.getMediaType();

        PKIException.Data data;
        String className;

        if (MediaType.APPLICATION_XML_TYPE.isCompatible(contentType)) {
            data = response.readEntity(PKIException.Data.class);
            className = data.getClassName();
            logger.info(className + ":\n" + data.toXML());

        } else if (MediaType.APPLICATION_JSON_TYPE.isCompatible(contentType)) {
            data = response.readEntity(PKIException.Data.class);
            className = data.getClassName();
            logger.info(className + ":\n" + data.toJSON());

        } else {
            throw new PKIException(status.getStatusCode(), status.getReasonPhrase());
        }

        Class<? extends PKIException> exceptionClass =
                Class.forName(className).asSubclass(PKIException.class);

        Constructor<? extends PKIException> constructor =
                exceptionClass.getConstructor(PKIException.Data.class);

        throw constructor.newInstance(data);
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

            return response.readEntity(clazz);

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

    public CryptoProvider getCrypto() {
        return crypto;
    }

    public void setCrypto(CryptoProvider crypto) {
        this.crypto = crypto;
    }

    public PKIConnection getConnection() {
        return connection;
    }

    public Response get(String path) throws Exception {
        return connection.target(path).request().get();
    }

    public <T> T get(String path, Class<T> responseType) throws Exception {
        return connection.target(path).request().get(responseType);
    }

    public Response post(String path) throws Exception {
        return connection.target(path).request().post(null);
    }

    public <T> T post(String path, Class<T> responseType) throws Exception {
        return connection.target(path).request().post(null, responseType);
    }

    public Response post(String path, MultivaluedMap<String, String> content) throws Exception {
        return connection.target(path).request().post(Entity.form(content));
    }

    public <T> T post(String path, MultivaluedMap<String, String> content, Class<T> responseType) throws Exception {
        return connection.target(path).request().post(Entity.form(content), responseType);
    }

    public Info getInfo() throws Exception {
        if (infoClient == null) {
            infoClient = new InfoClient(this);
            info = infoClient.getInfo();
        }
        return info;
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

    public void setOutput(File output) {
        connection.setOutput(output);
    }
}
