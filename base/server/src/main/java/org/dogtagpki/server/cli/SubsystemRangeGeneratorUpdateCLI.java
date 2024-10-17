//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import static com.netscape.cmscore.dbs.Repository.logger;
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
import java.math.BigInteger;
import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public abstract class SubsystemRangeGeneratorUpdateCLI extends SubsystemCLI {
    private static final Logger logger = LoggerFactory.getLogger(SubsystemRangeGeneratorUpdateCLI.class);
    protected IDGenerator idGenerator;

    public SubsystemRangeGeneratorUpdateCLI(CLI parent) {
        super("update", "Update " + parent.getParent().getParent().getName().toUpperCase() + " range generator", parent);
    }
    @Override
    public void createOptions() {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration");
        option.setArgName("password config");
        options.addOption(option);
        
        options.addOption("t", "type", true, "Generator type to update.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (!cmd.hasOption("type")) {
            throw new Exception("Missing generator type.");
        }
        String generatorType = cmd.getOptionValue("type");

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(PKILogger.LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(PKILogger.LogLevel.INFO);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            throw new Exception("Missing generator");
        }
        IDGenerator generator = IDGenerator.fromString(cmdArgs[0]);

        initializeTomcatJSS();
        String subsystem = parent.getParent().getParent().getName();
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

        if (generatorType.equals("cert")){
            updateSerialNumberRangeGenerator(
                    socketFactory,
                    connInfo,
                    authInfo,
                    dbConfig,
                    baseDN,
                    generator);
            cs.commit(false);
        } else if (generatorType.equals("request")) {
            updateRequestNumberRangeGenerator(
                    socketFactory,
                    connInfo,
                    authInfo,
                    dbConfig,
                    baseDN,
                    generator);
            cs.commit(false);
        } else {
            throw new EBaseException("Generator type " + generatorType + " not supported.");            
        }
    }

    protected void updateSerialNumberRangeGenerator(PKISocketFactory socketFactory, LdapConnInfo connInfo,
            LdapAuthInfo authInfo, DatabaseConfig dbConfig, String baseDN, IDGenerator newGenerator) throws Exception {
        
        if (newGenerator == IDGenerator.RANDOM && idGenerator != IDGenerator.RANDOM) {
            logger.debug("Remove serial ranges from configuration");
            dbConfig.remove(DatabaseConfig.MIN_SERIAL_NUMBER);
            dbConfig.remove(DatabaseConfig.MAX_SERIAL_NUMBER);
            dbConfig.remove(DatabaseConfig.SERIAL_INCREMENT);
            dbConfig.remove(DatabaseConfig.SERIAL_LOW_WATER_MARK);
            dbConfig.remove(DatabaseConfig.SERIAL_CLONE_TRANSFER_NUMBER);
            dbConfig.remove(DatabaseConfig.SERIAL_RANGE_DN);
            return;
        }
        if (newGenerator == IDGenerator.LEGACY_2 && idGenerator == IDGenerator.LEGACY) {
            logger.debug("Repository: Updating ranges entry to hex format");

            LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);
            try{
                String rangeDN = dbConfig.getSerialRangeDN() + "," + baseDN;

                String beginSerialNumber = dbConfig.getBeginSerialNumber();
                dbConfig.setBeginSerialNumber("0x" + beginSerialNumber);
                
                String endSerialNumber = dbConfig.getEndSerialNumber();
                LDAPEntry entrySerial = conn.read("cn=" + beginSerialNumber+"," + rangeDN);
                LDAPAttribute attrEnd = entrySerial.getAttribute("endRange");
                if (attrEnd != null) {
                    endSerialNumber = attrEnd.getStringValues().nextElement();
                }
                dbConfig.setEndSerialNumber("0x" + endSerialNumber);

                String serialIncrement = dbConfig.getSerialIncrement();
                dbConfig.setSerialIncrement("0x" + serialIncrement);

                String serialLowWaterMark = dbConfig.getSerialLowWaterMark();
                dbConfig.setSerialLowWaterMark("0x" + serialLowWaterMark);

                String serialCloneTransfer = dbConfig.getSerialCloneTransferNumber();
                dbConfig.setSerialCloneTransferNumber("0x" + serialCloneTransfer);

                String nextBeginSerial = dbConfig.getNextBeginSerialNumber();
                String nextEndSerial = dbConfig.getNextEndSerialNumber();
                if (nextBeginSerial != null && !nextBeginSerial.equals("-1")) {
                    dbConfig.setNextBeginSerialNumber("0x" + nextBeginSerial);
       
                    LDAPEntry entryNextSerial = conn.read("cn=" + nextBeginSerial + "," + rangeDN);
                    LDAPAttribute attrNextEnd = entryNextSerial.getAttribute("endRange");
                    if (attrNextEnd != null) {
                        nextEndSerial = attrNextEnd.getStringValues().nextElement();
                    }
                    dbConfig.setNextEndSerialNumber("0x" + nextEndSerial);
                }

                LDAPSearchResults results = conn.search(rangeDN, LDAPv3.SCOPE_SUB, "(objectClass=pkiRange)", null, false);

                BigInteger lastUsedSerial = BigInteger.ZERO;
                while (results.hasMoreElements()) {
                    LDAPEntry entry = results.next();
                    String endRange = entry.getAttribute("endRange").getStringValues().nextElement();
                    BigInteger next = new BigInteger(endRange, 16);
                    if (lastUsedSerial.compareTo(next) < 0) {
                        lastUsedSerial = next;
                    }
                }

                if (lastUsedSerial == BigInteger.ZERO) {
                    lastUsedSerial = new BigInteger(endSerialNumber, 16);
                }
                BigInteger nextSerialNumber = lastUsedSerial.add(BigInteger.ONE);
                String serialDN = dbConfig.getSerialDN() + "," + baseDN;
                // store nextRange as decimal
                LDAPAttribute attrSerialNextRange = new LDAPAttribute("nextRange", nextSerialNumber.toString());

                LDAPModification serialmod = new LDAPModification(LDAPModification.REPLACE, attrSerialNextRange);

                conn.modify(serialDN, serialmod);
            } finally {
                conn.disconnect();
            }
            return;
        }
        throw new EBaseException("Update to " + newGenerator + " not supported");
    }

    protected void updateRequestNumberRangeGenerator(PKISocketFactory socketFactory, LdapConnInfo connInfo,
            LdapAuthInfo authInfo, DatabaseConfig dbConfig, String baseDN, IDGenerator newGenerator) throws EBaseException {
        
        String value = dbConfig.getString(
                RequestRepository.PROP_REQUEST_ID_GENERATOR,
                RequestRepository.DEFAULT_REQUEST_ID_GENERATOR);
        idGenerator = IDGenerator.fromString(value);

        if (newGenerator == IDGenerator.RANDOM && idGenerator != IDGenerator.RANDOM) {
            logger.debug("Remove request ranges from configuration");
            dbConfig.remove(DatabaseConfig.MIN_REQUEST_NUMBER);
            dbConfig.remove(DatabaseConfig.MAX_REQUEST_NUMBER);
            dbConfig.remove(DatabaseConfig.REQUEST_INCREMENT);
            dbConfig.remove(DatabaseConfig.REQUEST_LOW_WATER_MARK);
            dbConfig.remove(DatabaseConfig.REQUEST_CLONE_TRANSFER_NUMBER);
            dbConfig.remove(DatabaseConfig.REQUEST_RANGE_DN);
            dbConfig.put(RequestRepository.PROP_REQUEST_ID_GENERATOR, newGenerator.toString());
            dbConfig.put(RequestRepository.PROP_REQUEST_ID_LENGTH, "128");
            return;
        }
        if (newGenerator == IDGenerator.LEGACY_2 && idGenerator == IDGenerator.LEGACY) {
            dbConfig.put(RequestRepository.PROP_REQUEST_ID_GENERATOR, newGenerator.toString());
            return;
        }
        throw new EBaseException("Update to " + newGenerator + " not supported");
    }
}