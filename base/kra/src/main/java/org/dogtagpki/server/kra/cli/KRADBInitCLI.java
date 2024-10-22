//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.cli;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.SubsystemDBInitCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.dbs.KeyRepository;
import com.netscape.cmscore.dbs.Repository.IDGenerator;

/**
 * @author Endi S. Dewata
 */
public class KRADBInitCLI extends SubsystemDBInitCLI {

    public static Logger logger = LoggerFactory.getLogger(KRADBInitCLI.class);

    public KRADBInitCLI(CLI parent) {
        super("init", "Initialize KRA database", parent);
    }

    @Override
    public void init(DatabaseConfig dbConfig) throws Exception {

        super.init(dbConfig);

        String value = dbConfig.getString(
                KeyRepository.PROP_KEY_ID_GENERATOR,
                KeyRepository.DEFAULT_KEY_ID_GENERATOR);
        serialIDGenerator = IDGenerator.fromString(value);
    }
}
