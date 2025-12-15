//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import java.security.SecureRandom;

import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;

/**
 * @author Endi S. Dewata
 */
public class CACertCLI extends CLI {

    public CACertCLI(CLI parent) {
        super("cert", "CA certificate management commands", parent);

        addModule(new CACertFindCLI(this));
        addModule(new CACertCreateCLI(this));
        addModule(new CACertImportCLI(this));
        addModule(new CACertRemoveCLI(this));

        addModule(new CACertRequestCLI(this));
    }

    public static Request importCertRequest(
            SecureRandom secureRandom,
            DBSubsystem dbSubsystem,
            RequestId requestID,
            String requestType,
            byte[] csrBytes,
            String[] dnsNames,
            ConfigStore profileConfig,
            boolean adjustValidity) throws Exception {

        CertRequestRepository requestRepository = new CertRequestRepository(secureRandom, dbSubsystem);
        requestRepository.init();

        // generate request ID if not provided
        if (requestID == null) {
            if (requestRepository.getIDGenerator() != IDGenerator.RANDOM) {
                throw new Exception("Unable to generate random request ID");
            }
            requestID = requestRepository.createRequestID();
        }

        Request request = requestRepository.createRequest(requestID, "enrollment");

        requestRepository.updateRequest(
                request,
                requestType,
                csrBytes,
                dnsNames);

        requestRepository.updateRequest(
                request,
                profileConfig.getString("id"),
                profileConfig.getString("profileIDMapping"),
                profileConfig.getString("profileSetIDMapping"),
                adjustValidity);

        requestRepository.updateRequest(request);

        return request;
    }
}
