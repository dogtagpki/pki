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
import java.net.URISyntaxException;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.dogtagpki.common.Range;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.account.AccountClient;
import com.netscape.certsrv.account.AccountInfo;
import com.netscape.certsrv.authentication.EAuthException;
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

    public SubsystemClient(PKIClient client, String name) throws URISyntaxException {
        // subsystem name should match the client name
        super(client, name, name);

        accountClient = new AccountClient(client, name);
        addClient(accountClient);
    }

    /**
     * Log in to the subsystem.
     */
    public AccountInfo login() throws Exception {
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

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("type", type);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionID);

        String response = client.post("/" + name + "/admin/" + name + "/updateNumberRange", content);
        logger.debug("Response: " + response);

        if (StringUtils.isEmpty(response)) {
            String message = "Unable to request " + type + " range";
            logger.error(message);
            throw new IOException(message);
        }

        // when the admin servlet is unavailable, we return a badly formatted error page
        XMLObject parser = new XMLObject(new ByteArrayInputStream(response.getBytes()));

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

    /**
     * Log out from the subsystem.
     */
    public void logout() throws Exception {
        accountClient.logout();
    }
}
