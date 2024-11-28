//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemDBInitCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.repository.IRepository.IDGenerator;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.dbs.CertificateRepository;
/**
 * @author Endi S. Dewata
 */
public class CADBInitCLI extends SubsystemDBInitCLI {
    public static Logger logger = LoggerFactory.getLogger(CADBInitCLI.class);
    public CADBInitCLI(CLI parent) {
        super("init", "Initialize CA database", parent);
    }
    @Override
    public void init(DatabaseConfig dbConfig) throws Exception {
        super.init(dbConfig);
        String value = dbConfig.getString(
                CertificateRepository.PROP_CERT_ID_GENERATOR,
                CertificateRepository.DEFAULT_CERT_ID_GENERATOR);
        serialIDGenerator = IDGenerator.fromString(value);
    }
}