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

    protected IDGenerator requestIDGenerator;
    protected IDGenerator serialIDGenerator;

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

    public void init(DatabaseConfig dbConfig) throws Exception {

        String value = dbConfig.getString(
                RequestRepository.PROP_REQUEST_ID_GENERATOR,
                RequestRepository.DEFAULT_REQUEST_ID_GENERATOR);
        requestIDGenerator = IDGenerator.fromString(value);
    }

    public String getRequestNextRangeDN(
            LDAPConfig ldapConfig,
            DatabaseConfig dbConfig) throws Exception {

        if (requestIDGenerator == IDGenerator.LEGACY_2) {
            // the request nextRange is stored in request repository's range DN
            return dbConfig.getRequestRangeDN() + "," + ldapConfig.getBaseDN();
        }

        // the request nextRange is stored in request repository's base DN
        return dbConfig.getRequestDN() + "," + ldapConfig.getBaseDN();
    }

    public String getSerialNextRangeDN(
            LDAPConfig ldapConfig,
            DatabaseConfig dbConfig) throws Exception {

        if (serialIDGenerator == IDGenerator.LEGACY_2) {
            // the cert/key nextRange is stored in cert/key repository's range DN
            return dbConfig.getSerialRangeDN() + "," + ldapConfig.getBaseDN();
        }

        // the cert/key nextRange is stored in cert/key repository's base DN
        return dbConfig.getSerialDN() + "," + ldapConfig.getBaseDN();
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
        init(dbConfig);

        updateSerialNumberRange(
                socketFactory,
                connInfo,
                authInfo,
                ldapConfig,
                dbConfig,
                baseDN);

        updateRequestNumberRange(
                socketFactory,
                connInfo,
                authInfo,
                ldapConfig,
                dbConfig,
                baseDN);
    }

    public void updateSerialNumberRange(
            PKISocketFactory socketFactory,
            LdapConnInfo connInfo,
            LdapAuthInfo authInfo,
            LDAPConfig ldapConfig,
            DatabaseConfig dbConfig,
            String baseDN) throws Exception {

        if (serialIDGenerator == IDGenerator.RANDOM) {
            logger.info("No need to update serial number range");
            return;
        }

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            String nextRangeDN = getSerialNextRangeDN(ldapConfig, dbConfig);
            logger.info("Updating serial next range in " + nextRangeDN);

            BigInteger endSerialNumber;
            if (serialIDGenerator == IDGenerator.LEGACY_2) {
                endSerialNumber = dbConfig.getBigInteger(DatabaseConfig.MAX_SERIAL_NUMBER);
            } else {
                // parse the end of current cert range as decimal
                // NOTE: this is a bug, cert range is stored as hex in CS.cfg
                endSerialNumber = new BigInteger(dbConfig.getEndSerialNumber());
            }
            BigInteger nextSerialNumber = endSerialNumber.add(BigInteger.ONE);

            // store nextRange as decimal
            logger.info("- next range: " + nextSerialNumber.toString() + " (0x" + nextSerialNumber.toString(16) + ")");
            LDAPAttribute attrSerialNextRange = new LDAPAttribute(DBSubsystem.PROP_NEXT_RANGE, nextSerialNumber.toString());

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
            LDAPConfig ldapConfig,
            DatabaseConfig dbConfig,
            String baseDN) throws Exception {

        if (requestIDGenerator == IDGenerator.RANDOM) {
            logger.info("No need to update request ID range");
            return;
        }

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            String nextRangeDN = getRequestNextRangeDN(ldapConfig, dbConfig);
            logger.info("Updating request ID next range in " + nextRangeDN);

            BigInteger endRequestNumber;
            if (requestIDGenerator == IDGenerator.LEGACY_2) {
                endRequestNumber = dbConfig.getBigInteger(DatabaseConfig.MAX_REQUEST_NUMBER);
            } else {
                // parse the end of current range as decimal
                endRequestNumber = new BigInteger(dbConfig.getEndRequestNumber());
            }
            BigInteger nextRequestNumber = endRequestNumber.add(BigInteger.ONE);

            // store nextRange as decimal
            LDAPAttribute attrRequestNextRange = new LDAPAttribute(DBSubsystem.PROP_NEXT_RANGE, nextRequestNumber.toString());

            LDAPModification requestmod = new LDAPModification(LDAPModification.REPLACE, attrRequestNextRange);

            conn.modify(nextRangeDN, requestmod);

        } finally {
            conn.disconnect();
        }
    }
}
