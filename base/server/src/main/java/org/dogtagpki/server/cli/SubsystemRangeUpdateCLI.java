//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;
import java.math.BigInteger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.dbs.repository.IRepository.IDGenerator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPModification;

/**
 * @author Endi S. Dewata
 */
public class SubsystemRangeUpdateCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemRangeUpdateCLI.class);

    protected IDGenerator serialIDGenerator = IDGenerator.LEGACY;
    protected IDGenerator requestIDGenerator = IDGenerator.LEGACY;

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
                null);
        if (value != null) {
            requestIDGenerator = IDGenerator.fromString(value);
        }

        value = dbConfig.getString(
                "cert.id.generator",
                null);
        if (value != null) {
            serialIDGenerator = IDGenerator.fromString(value);
        }
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

        String catalinaBase = System.getProperty("catalina.base");

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getName();
        String configFile = catalinaBase + File.separator + subsystem + File.separator +
                "conf" + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        EngineConfig cs = new EngineConfig(storage);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String baseDN = ldapConfig.getBaseDN();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);

        LdapAuthInfo authInfo = new LdapAuthInfo();
        authInfo.setPasswordStore(passwordStore);
        authInfo.init(
                authConfig,
                connInfo.getHost(),
                connInfo.getPort(),
                connInfo.getSecure());

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory;
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory = new PKISocketFactory(authInfo.getClientCertNickname());
        } else {
            socketFactory = new PKISocketFactory(connInfo.getSecure());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

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

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            String nextRangeDN = getSerialNextRangeDN(ldapConfig, dbConfig);
            logger.info("Updating serial next range in " + nextRangeDN);

            BigInteger endSerialNumber;
            if (serialIDGenerator == IDGenerator.LEGACY_2) {
                endSerialNumber = dbConfig.getBigInteger(DBSubsystem.PROP_MAX_SERIAL_NUMBER);
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

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            String nextRangeDN = getRequestNextRangeDN(ldapConfig, dbConfig);
            logger.info("Updating request ID next range in " + nextRangeDN);

            BigInteger endRequestNumber;
            if (requestIDGenerator == IDGenerator.LEGACY_2) {
                endRequestNumber = dbConfig.getBigInteger(DBSubsystem.PROP_MAX_REQUEST_NUMBER);
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
