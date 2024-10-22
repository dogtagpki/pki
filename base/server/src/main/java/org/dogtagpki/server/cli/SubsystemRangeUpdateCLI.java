//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.math.BigInteger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPModification;

/**
 * @author Endi S. Dewata
 */
public class SubsystemRangeUpdateCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemRangeUpdateCLI.class);

    public SubsystemRangeUpdateCLI(CLI parent) {
        super("update", "Update " + parent.getParent().getName().toUpperCase() + " ranges", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration");
        option.setArgName("password config");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        initializeTomcatJSS();
        String subsystem = parent.getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String baseDN = ldapConfig.getBaseDN();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);
        LdapAuthInfo authInfo = getAuthInfo(passwordStore, connInfo, ldapConfig);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        DatabaseConfig dbConfig = cs.getDatabaseConfig();

        // currently the cert nextRange is stored in cert repository's base DN
        String serialNextRangeDN = dbConfig.getSerialDN() + "," + baseDN;

        updateSerialNumberRange(
                socketFactory,
                connInfo,
                authInfo,
                dbConfig,
                serialNextRangeDN);

        // currently the request nextRange is stored in request repository's base DN
        String requestNextRangeDN = dbConfig.getRequestDN() + "," + baseDN;

        updateRequestNumberRange(
                socketFactory,
                connInfo,
                authInfo,
                dbConfig,
                requestNextRangeDN);
    }

    public void updateSerialNumberRange(
            PKISocketFactory socketFactory,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo,
            DatabaseConfig dbConfig,
            String nextRangeDN) throws Exception {

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            // parse the end of current cert range as decimal
            // NOTE: this is a bug, cert range is stored as hex in CS.cfg
            BigInteger endSerialNumber = new BigInteger(dbConfig.getEndSerialNumber());

            // generate nextRange in decimal
            String nextSerialNumber = endSerialNumber.add(BigInteger.ONE).toString();

            // store nextRange as decimal
            LDAPAttribute attrSerialNextRange = new LDAPAttribute(DBSubsystem.PROP_NEXT_RANGE, nextSerialNumber);

            LDAPModification serialmod = new LDAPModification(LDAPModification.REPLACE, attrSerialNextRange);

            conn.modify(nextRangeDN, serialmod);

        } finally {
            conn.disconnect();
        }
    }

    public void updateRequestNumberRange(
            PKISocketFactory socketFactory,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo,
            DatabaseConfig dbConfig,
            String nextRangeDN) throws Exception {

        String value = dbConfig.getString(
                RequestRepository.PROP_REQUEST_ID_GENERATOR,
                RequestRepository.DEFAULT_REQUEST_ID_GENERATOR);
        IDGenerator idGenerator = IDGenerator.fromString(value);

        if (idGenerator != IDGenerator.LEGACY) {
            logger.info("No need to update request ID range");
            return;
        }

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            logger.info("Updating request ID range");

            // parse the end of current range as decimal
            BigInteger endRequestNumber = new BigInteger(dbConfig.getEndRequestNumber());

            // generate nextRange in decimal
            String nextRequestNumber = endRequestNumber.add(BigInteger.ONE).toString();

            // store nextRange as decimal
            LDAPAttribute attrRequestNextRange = new LDAPAttribute(DBSubsystem.PROP_NEXT_RANGE, nextRequestNumber);

            LDAPModification requestmod = new LDAPModification(LDAPModification.REPLACE, attrRequestNextRange);

            conn.modify(nextRangeDN, requestmod);

        } finally {
            conn.disconnect();
        }
    }
}
