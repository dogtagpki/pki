//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.stream.Collectors;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngineConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
@WebServlet(
        name = "caInstallerServlet",
        urlPatterns = "/v2/installer/*")
public class CAInstallerServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(CAInstallerServlet.class);

    @WebAction(method = HttpMethod.POST, paths = {"createRequestID"})
    public void createRequestID(HttpServletRequest request, HttpServletResponse response) throws Exception {
        logger.info("CAInstallerServlet: Creating request ID");
        String requestData = request.getReader().lines().collect(Collectors.joining());
        CertificateSetupRequest certReqData = JSONSerializer.fromJSON(requestData, CertificateSetupRequest.class);
        try {
            validatePin(certReqData.getPin());

            CAEngineConfig cs = engine.getConfig();
            String csState = cs.getState() + "";

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            CertRequestRepository requestRepository = engine.getCertRequestRepository();
            RequestId requestID = requestRepository.createRequestID();
            logger.info("CAInstallerServlet: - request ID: {}", requestID.toHexString());
            PrintWriter out = response.getWriter();
            out.println(requestID.toJSON());
        } catch (Throwable e) {
            logger.error("Unable to create request ID: " + e.getMessage(), e);
            throw e;
        }
    }

    @WebAction(method = HttpMethod.POST, paths = {"createCertID"})
    public void createCertID(HttpServletRequest request, HttpServletResponse response) throws Exception {
        logger.info("CAInstallerServlet: Creating cert ID");
        String requestData = request.getReader().lines().collect(Collectors.joining());
        CertificateSetupRequest certReqData = JSONSerializer.fromJSON(requestData, CertificateSetupRequest.class);
        try {
            validatePin(certReqData.getPin());

            CAEngineConfig cs = engine.getConfig();
            String csState = cs.getState() + "";

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            CertificateRepository certificateRepository = engine.getCertificateRepository();
            BigInteger serialNumber = certificateRepository.getNextSerialNumber();
            CertId certID = new CertId(serialNumber);

            logger.info("CAInstallerServlet: - cert ID: {}", certID.toHexString());
            PrintWriter out = response.getWriter();
            out.println(certID.toJSON());
        } catch (Throwable e) {
            logger.error("Unable to create cert ID: " + e.getMessage(), e);
            throw e;
        }
    }

    private void validatePin(String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        CAEngineConfig cs = engine.getConfig();

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String preopPin = preopConfig.getString("pin");

        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }
}
