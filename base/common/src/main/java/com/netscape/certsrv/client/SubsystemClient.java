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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.dogtagpki.common.Range;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.databind.JsonNode;
import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.cmsutil.json.JSONObject;
import com.netscape.cmsutil.xml.XMLObject;


/**
 * @author Endi S. Dewata
 */
public class SubsystemClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(SubsystemClient.class);

    public static String SUCCESS = "0";
    public static String FAILURE = "1";
    public static String AUTH_FAILURE = "2";

    public AccountClient accountClient;

    public SubsystemClient(PKIClient client, String name) throws Exception {
        // subsystem name should match the client name
        super(client, name, name);

        accountClient = new AccountClient(client, name);
        addClient(accountClient);
    }

    /**
     * Log in to the subsystem.
     */
    public Account login() throws Exception {
        return accountClient.login();
    }

    public boolean exists() throws Exception {

        ClientConfig config = client.getConfig();
        URI serverURI = config.getServerURL().toURI();

        URI subsystemURI = new URI(
                serverURI.getScheme(),
                null,
                serverURI.getHost(),
                serverURI.getPort(),
                "/" + name,
                null,
                null);

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {

            HttpGet method = new HttpGet(subsystemURI);
            HttpResponse response = client.execute(method);
            int code = response.getStatusLine().getStatusCode();

            if (code == 200) {
                return true;

            } else if (code == 404) {
                return false;

            } else {
                throw new Exception("Error: " + response.getStatusLine());
            }
        }
    }

    public Range requestRange(String type, String sessionID) throws Exception {

        logger.info("Requesting " + type + " range");

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("type", type);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);

        String response = client.post(
                name + "/admin/" + name + "/updateNumberRange",
                content,
                String.class);
        logger.debug("Response: " + response);

        if (StringUtils.isEmpty(response)) {
            String message = "Unable to request " + type + " range";
            logger.error(message);
            throw new IOException(message);
        }

        try {
            return buildRangeFromJSONResponse(new ByteArrayInputStream(response.getBytes()));
        } catch (Exception e) {
            return buildRangeFromXMLResponse(new ByteArrayInputStream(response.getBytes()));
        }
    }

    private Range buildRangeFromJSONResponse(ByteArrayInputStream bais) throws IOException, EAuthException {
        // when the admin servlet is unavailable, we return a badly formatted error page
        JSONObject parser = new JSONObject(bais);

        JsonNode responseNode = parser.getJsonNode().get("Response");
        String status = responseNode.get("Status").asText();
        logger.debug("Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getJsonNode().get("Error").asText();
            throw new IOException(error);
        }

        String begin = responseNode.get("beginNumber").asText();
        logger.info("Begin: " + begin);

        String end = responseNode.get("endNumber").asText();
        logger.info("End: " + end);

        Range range = new Range();
        range.setBegin(begin);
        range.setEnd(end);
        return range;
        }

    @Deprecated(since = "11.0.0", forRemoval = true)
    private Range buildRangeFromXMLResponse(ByteArrayInputStream bais) throws IOException, EAuthException, SAXException, ParserConfigurationException {
        // when the admin servlet is unavailable, we return a badly formatted error page
        XMLObject parser = new XMLObject(bais);

        String status = parser.getValue("Status");
        logger.debug("Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }

        String begin = parser.getValue("beginNumber");
        logger.info("Begin: " + begin);

        String end = parser.getValue("endNumber");
        logger.info("End: " + end);

        Range range = new Range();
        range.setBegin(begin);
        range.setEnd(end);
        return range;
    }

    public void addUser(
            URI secdomainURI,
            String uid,
            String subsystemName,
            String subsystemCert,
            String sessionId) throws Exception {

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("uid", uid);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");
        content.putSingle("certificate", subsystemCert);
        content.putSingle("name", subsystemName);

        String path = name + "/admin/" + name + "/registerUser";
        String response = client.post(path, content, String.class);
        logger.debug("SubsystemClient: Response: " + response);

        if (response == null || response.equals("")) {
            logger.error("SubsystemClient: No response");
            throw new IOException("No response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        try {
            processJSONResponse(bis);
        } catch (Exception e) {
            processXMLResponse(bis);
        }
        logger.debug("SubsystemClient: Added user " + uid);
    }

    private void processJSONResponse(ByteArrayInputStream bis) throws EAuthException, IOException {
        JSONObject parser = new JSONObject(bis);
        JsonNode responseNode = parser.getJsonNode().get("Response");
        String status = responseNode.get("Status").asText();
        logger.debug("SubsystemClient: Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getJsonNode().get("Error").asText();
            throw new IOException(error);
        }
    }

    @Deprecated(since = "11.0.0", forRemoval = true)
    private void processXMLResponse(ByteArrayInputStream bis) throws EAuthException, IOException, SAXException, ParserConfigurationException {
        XMLObject parser = new XMLObject(bis);
        String status = parser.getValue("Status");
        logger.debug("SubsystemClient: Status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }
    }

    /**
     * Log out from the subsystem.
     */
    public void logout() throws Exception {
        accountClient.logout();
    }
}
