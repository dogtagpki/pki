//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.est;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

import org.mozilla.jss.netscape.security.pkcs.PKCS10;

import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;

/**
 * Request authorizer that invokes an external process to calculate
 * the authorization result.
 */
public class ExternalProcessRequestAuthorizer extends ESTRequestAuthorizer {

    public static org.slf4j.Logger logger =
        org.slf4j.LoggerFactory.getLogger(ExternalProcessRequestAuthorizer.class);

    static final String CONFIG_EXECUTABLE = "executable";
    static final String CONFIG_TIMEOUT = "timeout";

    static final long DEFAULT_TIMEOUT = 3;  // seconds

    static final String OPERATION_SIMPLEENROLL = "simpleenroll";
    static final String OPERATION_SIMPLEREENROLL = "simplereenroll";

    String executable;
    long timeout = DEFAULT_TIMEOUT;

    @Override
    public void start() throws Throwable {
        logger.info("Initializing ExternalProcessRequestAuthorizer");

        executable = config.getParameter(CONFIG_EXECUTABLE);
        if (executable == null) {
            throw new RuntimeException("ExternalProcessRequestAuthorizer: 'executable' property missing");
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
        return check(OPERATION_SIMPLEENROLL, data, csr);
    }

    @Override
    public Object authorizeSimplereenroll(
        ESTRequestAuthorizationData data, PKCS10 csr)
            throws PKIException {
        return check(OPERATION_SIMPLEREENROLL, data, csr);
    }

    String check(String op, ESTRequestAuthorizationData authzData, PKCS10 csr)
            throws PKIException {
        logger.debug("About to execute command: " + this.executable);
        ProcessBuilder pb = new ProcessBuilder(this.executable);

        // prepare object to be serialised to stdin of external process
        Data data = new Data();
        data.operation = op;
        data.authzData = authzData;
        data.csr = csr;
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
            generator.writeArray(roles, 0, roles.length);

            generator.writeEndObject();  // end principal

            generator.writeEndObject();
        }

    }

}
