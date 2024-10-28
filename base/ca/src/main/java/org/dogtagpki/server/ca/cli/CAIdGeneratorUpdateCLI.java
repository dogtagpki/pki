//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.cli;

import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.Repository;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemIdGeneratorUpdateCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class CAIdGeneratorUpdateCLI extends SubsystemIdGeneratorUpdateCLI {
    private static final Logger logger = LoggerFactory.getLogger(CAIdGeneratorUpdateCLI.class);

    public CAIdGeneratorUpdateCLI(CLI parent) {
        super(parent);
    }

    @Override
    protected void updateSerialNumberRangeGenerator(LdapBoundConnection conn,
            DatabaseConfig dbConfig, String baseDN, String newRangesName,
            IDGenerator newGenerator, String hostName, String securePort) throws Exception {
        String value = dbConfig.getString(
                CertificateRepository.PROP_CERT_ID_GENERATOR,
                CertificateRepository.DEFAULT_CERT_ID_GENERATOR);
        idGenerator = IDGenerator.fromString(value);

        if (newGenerator == IDGenerator.RANDOM && idGenerator != IDGenerator.RANDOM) {
            dbConfig.put(CertificateRepository.PROP_CERT_ID_GENERATOR, newGenerator.toString());
            dbConfig.put(CertificateRepository.PROP_CERT_ID_LENGTH, "128");
            dbConfig.remove("enableRandomSerialNumbers");
            dbConfig.remove("randomSerialNumberCounter");
        }
        if (newGenerator == IDGenerator.LEGACY_2 && idGenerator == IDGenerator.LEGACY) {
            dbConfig.put(CertificateRepository.PROP_CERT_ID_GENERATOR, newGenerator.toString());
            dbConfig.put(CertificateRepository.PROP_CERT_ID_RADIX, Integer.toString(Repository.HEX));
        }

        super.updateSerialNumberRangeGenerator(conn, dbConfig, baseDN, newRangesName, newGenerator, hostName, securePort);
    }

    
}
