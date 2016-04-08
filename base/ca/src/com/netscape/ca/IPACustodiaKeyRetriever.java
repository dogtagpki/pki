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

import java.lang.Process;
import java.lang.ProcessBuilder;
import java.util.Collection;
import java.util.Stack;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;

import com.netscape.certsrv.apps.CMS;

public class IPACustodiaKeyRetriever implements KeyRetriever {
    public Result retrieveKey(String nickname, Collection<String> hostPorts) {
        CMS.debug("Running IPACustodiaKeyRetriever");

        Stack<String> command = new Stack<>();
        command.push("/usr/libexec/pki-ipa-retrieve-key");
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

                /* Custodia returns a PEM-encoded certificate and a
                 * base64-encoded PKIArchiveOptions containing the
                 * wrapped private key.  These values are output by
                 * the Python 'pki-ipa-retrieve-key' program,
                 * separated by a null byte (password first)
                 */
                byte[] output = IOUtils.toByteArray(p.getInputStream());
                int splitIndex = ArrayUtils.indexOf(output, (byte) 0);
                if (splitIndex == ArrayUtils.INDEX_NOT_FOUND) {
                    CMS.debug("Invalid output: null byte not found");
                    continue;
                }
                return new Result(
                    ArrayUtils.subarray(output, 0, splitIndex),
                    ArrayUtils.subarray(output, splitIndex + 1, output.length)
                );
            } catch (Throwable e) {
                CMS.debug("Caught exception while executing command: " + e);
            } finally {
                command.pop();
            }
        }
        CMS.debug("Failed to retrieve key from any host.");
        return null;
    }
}
