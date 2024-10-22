//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.cli;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemRangeUpdateCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketFactory;

/**
 * @author Endi S. Dewata
 */
public class KRARangeUpdateCLI extends SubsystemRangeUpdateCLI {

    public static final Logger logger = LoggerFactory.getLogger(KRARangeUpdateCLI.class);

    public KRARangeUpdateCLI(CLI parent) {
        super(parent);
    }

    @Override
    public void init(DatabaseConfig dbConfig) throws Exception {

        super.init(dbConfig);

       String value = dbConfig.getString(
                KeyRepository.PROP_KEY_ID_GENERATOR,
                KeyRepository.DEFAULT_KEY_ID_GENERATOR);
        serialIDGenerator = IDGenerator.fromString(value);
    }

    @Override
    public void updateSerialNumberRange(
            PKISocketFactory socketFactory,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo,
            DatabaseConfig dbConfig,
            String baseDN) throws Exception {

        if (serialIDGenerator == IDGenerator.RANDOM) {
            logger.info("No need to update key ID range");
            return;
        }

        logger.info("Updating key ID range");

        super.updateSerialNumberRange(
                socketFactory,
                connInfo,
                authInfo,
                dbConfig,
                baseDN);
    }
}
