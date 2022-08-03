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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.ca;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Stack;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmsutil.json.JSONObject;


public class ExternalProcessKeyRetriever implements KeyRetriever {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ExternalProcessKeyRetriever.class);

    protected String executable;

    public ExternalProcessKeyRetriever(ConfigStore config) {
        if (config == null)
            throw new IllegalArgumentException("Missing config");

        try {
            this.executable = config.getString("executable");
        } catch (EPropertyNotFound e) {
            throw new IllegalArgumentException("Missing 'executable' config property");
        } catch (EBaseException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Result retrieveKey(String nickname, Collection<String> hostPorts) {

        logger.info("ExternalProcessKeyRetriever: Retrieving " + nickname + " key");

        Stack<String> command = new Stack<>();
        command.push(this.executable);
        command.push(nickname);

        for (String hostPort : hostPorts) {
            String host = hostPort.split(":")[0];
            command.push(host);
            logger.debug("ExternalProcessKeyRetriever: Command: " + command);

            ProcessBuilder pb = new ProcessBuilder(command)
                .redirectError(ProcessBuilder.Redirect.INHERIT);

            try {
                Process p = pb.start();
                int exitValue = p.waitFor();

                if (exitValue != 0) {
                    logger.warn("Unable to retrieve " + nickname + " key from " + host + ": RC=" + exitValue);
                    continue;
                }

                return parseResult(p.getInputStream());

            } catch (Throwable e) {
                logger.warn("Unable to retrieve " + nickname + " key from " + host + ": " + e.getMessage(), e);

            } finally {
                command.pop();
            }
        }

        logger.error("Unable to retrieve " + nickname + " key");
        return null;
    }

    /**
     * Read a PEM-encoded certificate and a base64-encoded
     * PKIArchiveOptions containing the wrapped private key.
     * Data is expected to be a JSON object with keys "certificate"
     * and "wrapped_key".
     */
    private Result parseResult(InputStream in) throws IOException {

        String result = new String(in.readAllBytes());
        logger.debug("ExternalProcessKeyRetriever: Result:\n" + result);

        JsonNode root = new JSONObject(result).getJsonNode();

        JsonNode certNode = root.path("certificate");

        if (certNode.isMissingNode()) {
            throw new RuntimeException("Missing \"certificate\" node");
        }

        if (!certNode.isTextual()) {
            throw new RuntimeException("Invalid \"certificate\" node: " + certNode);
        }

        String cert = certNode.textValue(); // won't return null

        if (StringUtils.isEmpty(cert)) {
            throw new RuntimeException("Missing \"certificate\" value");
        }

        JsonNode wrappedKeyNode = root.path("wrapped_key");

        if (wrappedKeyNode.isMissingNode()) {
            throw new RuntimeException("Missing \"wrapped_key\" node");
        }
        // won't return null, but throws IOException if base64 decoding fails
        byte[] pao = wrappedKeyNode.binaryValue();

        if (pao.length == 0) {
            throw new RuntimeException("Missing \"wrapped_key\" value");
        }

        return new Result(cert.getBytes(), pao);
    }
}
