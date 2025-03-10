//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.realm.PKIPrincipal;

/**
 * Request authorizer that invokes an external process to calculate
 * the authorization result.
 */
public class ExternalProcessRequestAuthorizer extends ESTRequestAuthorizer {

    public static org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(ExternalProcessRequestAuthorizer.class);

    static final String CONFIG_EXECUTABLE = "executable";
    static final String CONFIG_TIMEOUT = "timeout";
    static final String CONFIG_ENROLL_MATCH_SUBJ_SAN = "enrollMatchTLSSubjSAN";

    static final long DEFAULT_TIMEOUT = 3;  // seconds

    static final String OPERATION_SIMPLEENROLL = "simpleenroll";
    static final String OPERATION_SIMPLEREENROLL = "simplereenroll";

    String executable;
    boolean enrollMatchSubjSAN = true;

    long timeout = DEFAULT_TIMEOUT;

    @Override
    public void start() throws Throwable {
        logger.info("Initializing ExternalProcessRequestAuthorizer");

        executable = config.getParameter(CONFIG_EXECUTABLE);
        if (executable == null) {
            throw new RuntimeException("ExternalProcessRequestAuthorizer: 'executable' property missing");
        }

        String match = config.getParameter(CONFIG_ENROLL_MATCH_SUBJ_SAN);
        if (match != null && !match.isBlank()) {
            enrollMatchSubjSAN = Boolean.parseBoolean(match);
        }

        String timeoutConfig = config.getParameter(CONFIG_TIMEOUT);
        if (timeoutConfig != null && !timeoutConfig.isEmpty()) {
            timeout = Integer.valueOf(timeoutConfig).longValue();
            if (timeout < 1) {
                throw new IllegalArgumentException("Invalid timeout value: must be positive");
            }
        }
    }

    @Override
    public Object authorizeSimpleenroll(
        ESTRequestAuthorizationData data, PKCS10 csr)
            throws PKIException {
        if (enrollMatchSubjSAN) {
            if (data.clientCertChain != null && data.clientCertChain.length > 0) {
                ensureCSRMatchesToBeCert(csr, data.clientCertChain[0], false);
            } else {
                if(data.principal instanceof PKIPrincipal principal) {
                    ensureCSRMatchesToBeCert(csr, principal.getUser());
                }
            }
        }
        return check(OPERATION_SIMPLEENROLL, data, csr, null);
    }

    @Override
    public Object authorizeSimplereenroll(
        ESTRequestAuthorizationData data, PKCS10 csr, X509Certificate toBeRenewed)
            throws PKIException {
        ensureCSRMatchesToBeCert(csr, toBeRenewed, true);
        return check(OPERATION_SIMPLEREENROLL, data, csr, toBeRenewed);
    }


    private String check(
            String op,
            ESTRequestAuthorizationData authzData,
            PKCS10 csr,
            X509Certificate toBeRenewed)
            throws PKIException {
        logger.debug("About to execute command: " + this.executable);
        ProcessBuilder pb = new ProcessBuilder(this.executable);

        // prepare object to be serialised to stdin of external process
        Data data = new Data();
        data.operation = op;
        data.authzData = authzData;
        data.csr = csr;
        data.toBeRenewed = toBeRenewed;
        ObjectMapper mapper = new ObjectMapper();

        Process p;
        String stdout = "";
        String stderr = "";
        boolean timedOut;
        try {
            p = pb.start();

            // write request data to stdin
            mapper.writeValue(p.getOutputStream(), data);

            // wait for process to terminate, up to timeout
            timedOut = !p.waitFor(timeout, TimeUnit.SECONDS);
            if (timedOut) {
                p.destroyForcibly();
            } else {
                stdout = IOUtils.toString(p.getInputStream(), "UTF-8");
                stderr = IOUtils.toString(p.getErrorStream(), "UTF-8");
            }
        } catch (Throwable e) {
            String msg = "Caught exception while executing command: " + this.executable;
            logger.error(msg + ": " + e.getMessage(), e);
            throw new ForbiddenException(msg, e);
        }
        if (timedOut)
            throw new PKIException("Request validation timed out");
        int exitValue = p.exitValue();
        logger.debug("ExternalProcessRequestAuthorizer: exit value: " + exitValue);
        logger.debug("ExternalProcessRequestAuthorizer: stdout: " + stdout);
        logger.debug("ExternalProcessRequestAuthorizer: stderr: " + stderr);
        if (exitValue != 0)
            throw new ForbiddenException(stdout);

        return stdout;
    }


    static class Data {

        @JsonProperty("operation")
        String operation;

        @JsonProperty("authzData")
        @JsonSerialize(using=ESTRequestAuthorizationDataSerializer.class)
        ESTRequestAuthorizationData authzData;

        PKCS10 csr;

        @JsonProperty("csr")
        String getCSR() throws IOException {
            return Base64.encodeBase64String(csr.toByteArray());
        }

        X509Certificate toBeRenewed;

        @JsonProperty("toBeRenewed")
        @JsonInclude(JsonInclude.Include.NON_NULL)
        String getToBeRenewed() throws CertificateEncodingException {
            if (null == toBeRenewed) return null;
            return Base64.encodeBase64String(toBeRenewed.getEncoded());
        }

    }


    public static class ESTRequestAuthorizationDataSerializer
            extends StdSerializer<ESTRequestAuthorizationData> {

        public ESTRequestAuthorizationDataSerializer() {
            this(null);
        }

        public ESTRequestAuthorizationDataSerializer(Class<ESTRequestAuthorizationData> t) {
            super(t);
        }

        @Override
        public void serialize(
                ESTRequestAuthorizationData data,
                JsonGenerator generator,
                SerializerProvider provider)
                    throws IOException {
            generator.writeStartObject();

            generator.writeStringField("remoteAddr", data.remoteAddr);

            if (data.label.isPresent()) {
                generator.writeObjectField("label", data.label.get());
            }

            // principal
            generator.writeObjectFieldStart("principal");
            generator.writeStringField("name", data.principal.getName());

            // principal.roles
            String[] roles = { };
            if (data.principal instanceof GenericPrincipal) {
                roles = ((GenericPrincipal) data.principal).getRoles();
            }
            generator.writeFieldName("roles");

            // use this code to work with Jackson 2.10
            generator.writeStartArray();
            for (String role : roles) {
                generator.writeString(role);
            }
            generator.writeEndArray();

            // TODO: if Jackson 2.10 no longer needs to be
            // supported, replace the above code with this:
            // generator.writeArray(roles, 0, roles.length);

            generator.writeEndObject();  // end principal

            // client certs
            if (data.clientCertChain != null) {
                generator.writeArrayFieldStart("clientCertChain");
                for (int i = 0; i < data.clientCertChain.length; i++) {
                    try {
                        generator.writeString(
                            Base64.encodeBase64String(data.clientCertChain[i].getEncoded()));
                    } catch (CertificateEncodingException e) {
                        logger.error(
                            "ExternalProcessRequestAuthorizer: error encoding client certificate: " + e,
                            e
                        );
                        // Write a null as a placeholder for the bad cert.
                        // This is a "shouldn't happen" scenario... in theory
                        generator.writeNull();
                    }
                }
                generator.writeEndArray();
            }

            generator.writeEndObject();
        }

    }

}
