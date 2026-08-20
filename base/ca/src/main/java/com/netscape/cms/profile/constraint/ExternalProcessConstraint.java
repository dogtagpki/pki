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

import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.IOUtils;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.PolicyConstraintConfig;
import com.netscape.cms.profile.input.CertReqInput;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;


/**
 * Profile policy constraint that validates a certificate request
 * by executing an external process.  The process receives
 * request data via environment variables and indicates approval
 * by exiting with status 0 (non-zero rejects the request).
 *
 * <h2>Profile configuration parameters</h2>
 * <dl>
 *   <dt>{@code executable}</dt>
 *   <dd>Absolute path of the program to execute.  Required.</dd>
 *   <dt>{@code timeout}</dt>
 *   <dd>Maximum execution time in seconds (default&nbsp;10).
 *       The process is killed if the timeout expires and the
 *       request is rejected.</dd>
 * </dl>
 *
 * <h2>Security: executable allowlist</h2>
 *
 * Because certificate profiles can be created and modified via
 * the REST API, the {@code executable} parameter is checked
 * against an allowlist in CS.cfg at profile load time:
 *
 * <pre>
 * ca.externalProcessConstraint.allowedExecutables=/usr/libexec/pki/ipa-cert-check,/usr/libexec/pki/other-hook
 * </pre>
 *
 * Only exact, complete absolute paths are matched (no globs or
 * directory prefixes).  If the parameter is absent or empty, no
 * executables are permitted and any profile that uses this
 * constraint will fail to load.
 *
 * <h2>Environment variables</h2>
 *
 * The following variables are set in the process environment
 * (values come from the certificate request):
 * <ul>
 *   <li>{@code DOGTAG_CERT_REQUEST} &ndash; the PEM certificate request</li>
 *   <li>{@code DOGTAG_USER} &ndash; authenticated user ID</li>
 *   <li>{@code DOGTAG_PROFILE_ID} &ndash; profile that is being used</li>
 *   <li>{@code DOGTAG_AUTHORITY_ID} &ndash; issuing authority ID</li>
 *   <li>{@code DOGTAG_USER_DATA} &ndash; opaque user-supplied data</li>
 * </ul>
 *
 * Additional environment variables can be configured via
 * {@code params.env.*} sub-keys in the constraint configuration.
 */
public class ExternalProcessConstraint extends EnrollConstraint {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ExternalProcessConstraint.class);

    public static final String CONFIG_EXECUTABLE = "executable";
    public static final String CONFIG_TIMEOUT = "timeout";

    public static final long DEFAULT_TIMEOUT = 10;

    /* Map of envvars to include, and the corresponding Request keys
     *
     * All keys will be prefixed with "DOGTAG_" when added to environment.
     */
    protected static final Map<String, String> envVars = new TreeMap<>();

    protected Map<String, String> extraEnvVars = new TreeMap<>();

    static {
        envVars.put("DOGTAG_CERT_REQUEST", CertReqInput.VAL_CERT_REQUEST);
        envVars.put("DOGTAG_USER",
            Request.AUTH_TOKEN_PREFIX + "." + AuthToken.USER_ID);
        envVars.put("DOGTAG_PROFILE_ID", Request.PROFILE_ID);
        envVars.put("DOGTAG_AUTHORITY_ID", Request.AUTHORITY_ID);
        envVars.put("DOGTAG_USER_DATA", Request.USER_DATA);
    }

    protected String executable;
    protected long timeout;

    public ExternalProcessConstraint() {
        addConfigName(CONFIG_EXECUTABLE);
        addConfigName(CONFIG_TIMEOUT);
    }

    @Override
    public void init(PolicyConstraintConfig config) throws EProfileException {
        super.init(config);

        this.executable = getConfig(CONFIG_EXECUTABLE);
        if (this.executable == null || this.executable.isEmpty()) {
            throw new EProfileException(
                "Missing required config param 'executable'");
        }

        List<String> allowed;
        try {
            allowed = CAEngine.getInstance().getConfig().getCAConfig()
                .getExternalProcessConstraintAllowedExecutables();
        } catch (EBaseException e) {
            throw new EProfileException(
                "Failed to check executable allowlist: " + e.getMessage(), e);
        }
        if (!allowed.contains(this.executable)) {
            throw new EProfileException(
                "Executable not in"
                + " ca.externalProcessConstraint.allowedExecutables:"
                + " " + this.executable);
        }

        timeout = DEFAULT_TIMEOUT;
        String timeoutConfig = getConfig(CONFIG_TIMEOUT);
        if (timeoutConfig != null && !timeoutConfig.isEmpty()) {
            try {
                timeout = Integer.valueOf(timeoutConfig).longValue();
            } catch (NumberFormatException e) {
                throw new EProfileException("Invalid timeout value", e);
            }
            if (timeout < 1) {
                throw new EProfileException(
                    "Invalid timeout value: must be positive");
            }
        }

        ConfigStore envConfig = config.getSubStore("params.env", ConfigStore.class);
        Enumeration<String> names = envConfig.getPropertyNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            try {
                extraEnvVars.put(name, envConfig.getString(name));
            } catch (EBaseException e) {
                // shouldn't happen; log and move on
                logger.warn(
                    "ExternalProcessConstraint: caught exception processing "
                    + "'params.env' config: " + e.getMessage(), e
                );

            }
        }
    }

    @Override
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

    @Override
    public void validate(Request request, X509CertInfo info)
            throws ERejectException {
        logger.debug("About to execute command: " + this.executable);
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
                stdout = IOUtils.toString(p.getInputStream(), "UTF-8");
                stderr = IOUtils.toString(p.getErrorStream(), "UTF-8");
        } catch (Throwable e) {
            String msg =
                "Caught exception while executing command: " + this.executable;
            logger.error(msg + ": " + e.getMessage(), e);
            throw new ERejectException(msg, e);
        }
        if (timedOut)
            throw new ERejectException("Request validation timed out");
        int exitValue = p.exitValue();
        logger.debug("ExternalProcessConstraint: exit value: " + exitValue);
        logger.debug("ExternalProcessConstraint: stdout: " + stdout);
        logger.debug("ExternalProcessConstraint: stderr: " + stderr);
        if (exitValue != 0)
            throw new ERejectException(stdout);
    }

}
