//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.cli;

import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.dbs.Repository;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemIdGeneratorUpdateCLI;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class kraIdGeneratorUpdateCLI extends SubsystemIdGeneratorUpdateCLI {

    public kraIdGeneratorUpdateCLI(CLI parent) {
        super(parent);
    }

    @Override
    protected void updateSerialNumberRangeGenerator(PKISocketFactory socketFactory, LdapConnInfo connInfo,
            LdapAuthInfo authInfo, DatabaseConfig dbConfig, String baseDN, Repository.IDGenerator newGenerator, String hostName, String securePort) throws Exception {
        String value = dbConfig.getString(
                KeyRepository.PROP_KEY_ID_GENERATOR,
                KeyRepository.DEFAULT_KEY_ID_GENERATOR);
        idGenerator = Repository.IDGenerator.fromString(value);

        if (newGenerator == Repository.IDGenerator.RANDOM && idGenerator != Repository.IDGenerator.RANDOM) {
            dbConfig.put(KeyRepository.PROP_KEY_ID_GENERATOR, newGenerator.toString());
            dbConfig.put(KeyRepository.PROP_KEY_ID_LENGTH, "128");
        }
        if (newGenerator == Repository.IDGenerator.LEGACY_2 && idGenerator == Repository.IDGenerator.LEGACY) {
            dbConfig.put(KeyRepository.PROP_KEY_ID_GENERATOR, newGenerator.toString());
            dbConfig.put(KeyRepository.PROP_KEY_ID_RADIX, Integer.toString(Repository.HEX));
        }

        super.updateSerialNumberRangeGenerator(socketFactory, connInfo, authInfo, dbConfig, baseDN, newGenerator, hostName, securePort);
    }
}
