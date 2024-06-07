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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest.v1;

import java.math.BigInteger;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;

/**
 * @author alee
 *
 */
@Path("installer")
public class CAInstallerService extends PKIService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAInstallerService.class);

    public CAInstallerService() throws Exception {
    }

    public void validatePin(String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        CAEngine engine = (CAEngine) getCMSEngine();
        CAEngineConfig cs = engine.getConfig();

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String preopPin = preopConfig.getString("pin");

        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }

    @POST
    @Path("createRequestID")
    public RequestId createRequestID(CertificateSetupRequest request) throws Exception {

        logger.info("CAInstallerService: Creating request ID");

        try {
            validatePin(request.getPin());

            CAEngine engine = (CAEngine) getCMSEngine();
            CAEngineConfig cs = engine.getConfig();
            String csState = cs.getState() + "";

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            CertRequestRepository requestRepository = engine.getCertRequestRepository();

            RequestId requestID = requestRepository.createRequestID();
            logger.info("CAInstallerService: - request ID: " + requestID.toHexString());

            return requestID;

        } catch (Throwable e) {
            logger.error("Unable to create request ID: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("createCertID")
    public CertId createCertID(CertificateSetupRequest request) throws Exception {

        logger.info("CAInstallerService: Creating cert ID");

        try {
            validatePin(request.getPin());

            CAEngine engine = (CAEngine) getCMSEngine();
            CAEngineConfig cs = engine.getConfig();
            String csState = cs.getState() + "";

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            CertificateRepository certificateRepository = engine.getCertificateRepository();

            BigInteger serialNumber = certificateRepository.getNextSerialNumber();
            CertId certID = new CertId(serialNumber);

            logger.info("CAInstallerService: - cert ID: " + certID.toHexString());

            return certID;

        } catch (Throwable e) {
            logger.error("Unable to create cert ID: " + e.getMessage(), e);
            throw e;
        }
    }
}
