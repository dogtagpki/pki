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
import java.lang.Process;
import java.lang.ProcessBuilder;
import java.util.Collection;
import java.util.Stack;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.JsonNode;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;


public class ExternalProcessKeyRetriever implements KeyRetriever {
    protected String executable;

    public ExternalProcessKeyRetriever(IConfigStore config) {
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

    public Result retrieveKey(String nickname, Collection<String> hostPorts) {
        CMS.debug("Running ExternalProcessKeyRetriever");

        Stack<String> command = new Stack<>();
        command.push(this.executable);
        command.push(nickname);

        for (String hostPort : hostPorts) {
            String host = hostPort.split(":")[0];
            command.push(host);
            CMS.debug("About to execute command: " + command);
            ProcessBuilder pb = new ProcessBuilder(command);
            try {
                Process p = pb.start();
                int exitValue = p.waitFor();
                if (exitValue != 0)
                    continue;
                return parseResult(p.getInputStream());
            } catch (Throwable e) {
                CMS.debug("Caught exception while executing command: " + e);
            } finally {
                command.pop();
            }
        }
        CMS.debug("Failed to retrieve key from any host.");
        return null;
    }

    /* Read a PEM-encoded certificate and a base64-encoded
     * PKIArchiveOptions containing the wrapped private key.
     * Data is expected to be a JSON object with keys "certificate"
     * and "wrapped_key".
     */
    private Result parseResult(InputStream in) throws IOException {
        JsonNode root = (new ObjectMapper()).readTree(in);
        String cert = root.path("certificate").getTextValue();
        byte[] pao = root.path("wrapped_key").getBinaryValue();
        if (cert == null)
            throw new RuntimeException("missing \"certificate\" field");
        if (pao == null)
            throw new RuntimeException("missing \"wrapped_key\" field");
        return new Result(cert.getBytes(), pao);
    }
}
