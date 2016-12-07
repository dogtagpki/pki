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
// (C) 2016, 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.profile.constraint;

import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.input.CertReqInput;

import netscape.security.x509.X509CertInfo;


public class ExternalProcessConstraint extends EnrollConstraint {

    public static final String CONFIG_EXECUTABLE = "executable";
    public static final String CONFIG_TIMEOUT = "timeout";

    public static final long DEFAULT_TIMEOUT = 10;

    /* Map of envvars to include, and the corresponding IRequest keys
     *
     * All keys will be prefixed with "DOGTAG_" when added to environment.
     */
    protected static final Map<String, String> envVars = new TreeMap<>();

    protected Map<String, String> extraEnvVars = new TreeMap<>();

    static {
        envVars.put("DOGTAG_CERT_REQUEST", CertReqInput.VAL_CERT_REQUEST);
        envVars.put("DOGTAG_USER",
            IRequest.AUTH_TOKEN_PREFIX + "." + IAuthToken.USER_ID);
        envVars.put("DOGTAG_PROFILE_ID", IRequest.PROFILE_ID);
        envVars.put("DOGTAG_AUTHORITY_ID", IRequest.AUTHORITY_ID);
        envVars.put("DOGTAG_USER_DATA", IRequest.USER_DATA);
    }

    protected String executable;
    protected long timeout;

    public ExternalProcessConstraint() {
        addConfigName(CONFIG_EXECUTABLE);
        addConfigName(CONFIG_TIMEOUT);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);

        this.executable = getConfig(CONFIG_EXECUTABLE);
        if (this.executable == null || this.executable.isEmpty()) {
            throw new EProfileException(
                "Missing required config param 'executable'");
        }

        timeout = DEFAULT_TIMEOUT;
        String timeoutConfig = getConfig(CONFIG_TIMEOUT);
        if (this.executable != null && !this.executable.isEmpty()) {
            try {
                timeout = (new Integer(timeoutConfig)).longValue();
            } catch (NumberFormatException e) {
                throw new EProfileException("Invalid timeout value", e);
            }
            if (timeout < 1) {
                throw new EProfileException(
                    "Invalid timeout value: must be positive");
            }
        }

        IConfigStore envConfig = config.getSubStore("params.env");
        Enumeration<String> names = envConfig.getPropertyNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            try {
                extraEnvVars.put(name, envConfig.getString(name));
            } catch (EBaseException e) {
                // shouldn't happen; log and move on
                CMS.debug(
                    "ExternalProcessConstraint: caught exception processing "
                    + "'params.env' config: " + e
                );

            }
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_EXECUTABLE)) {
            return new Descriptor(
                IDescriptor.STRING, null, null, "Executable path");
        } else if (name.equals(CONFIG_TIMEOUT)) {
            return new Descriptor(
                IDescriptor.INTEGER, null, null, "Timeout in seconds");
        } else {
            return null;
        }
    }

    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        CMS.debug("About to execute command: " + this.executable);
        ProcessBuilder pb = new ProcessBuilder(this.executable);

        // set up process environment
        Map<String, String> env = pb.environment();
        for (String k : envVars.keySet()) {
            String v = request.getExtDataInString(envVars.get(k));
            if (v != null)
                env.put(k, v);
        }
        for (String k : extraEnvVars.keySet()) {
            String v = request.getExtDataInString(extraEnvVars.get(k));
            if (v != null)
                env.put(k, v);
        }

        Process p;
        String stdout = "";
        String stderr = "";
        boolean timedOut;
        try {
            p = pb.start();
            timedOut = !p.waitFor(timeout, TimeUnit.SECONDS);
            if (timedOut)
                p.destroyForcibly();
            else
                stdout = IOUtils.toString(p.getInputStream());
                stderr = IOUtils.toString(p.getErrorStream());
        } catch (Throwable e) {
            String msg =
                "Caught exception while executing command: " + this.executable;
            CMS.debug(msg);
            CMS.debug(e);
            throw new ERejectException(msg, e);
        }
        if (timedOut)
            throw new ERejectException("Request validation timed out");
        int exitValue = p.exitValue();
        CMS.debug("ExternalProcessConstraint: exit value: " + exitValue);
        CMS.debug("ExternalProcessConstraint: stdout: " + stdout);
        CMS.debug("ExternalProcessConstraint: stderr: " + stderr);
        if (exitValue != 0)
            throw new ERejectException(stdout);
    }

}
