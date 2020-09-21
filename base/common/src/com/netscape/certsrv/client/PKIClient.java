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

import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashSet;

import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoClient;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

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
        return connection.createProxy(path, clazz);
    }

    public String getSubsystem() {
        return config.getSubsystem();
    }

    public <T> T getEntity(Response response, Class<T> clazz) throws Exception {
        return connection.getEntity(response, clazz);
    }

    public <T> T getEntity(Response response, GenericType<T> clazz) throws Exception {
        return connection.getEntity(response, clazz);
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

    public String get(String path) throws Exception {
        return connection.get(path, String.class);
    }

    public String post(String path) throws Exception {
        return connection.post(path, String.class);
    }

    public String post(String path, MultivaluedMap<String, String> content) throws Exception {
        return connection.post(path, content);
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
}
