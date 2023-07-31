//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.cli;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.io.IOUtils;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;
import org.dogtagpki.server.ocsp.OCSPConfig;
import org.dogtagpki.server.ocsp.OCSPEngineConfig;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;
import com.netscape.ocsp.OCSPAuthority;

/**
 * @author Endi S. Dewata
 */
public class OCSPCRLIssuingPointAddCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(OCSPCRLIssuingPointAddCLI.class);

    public OCSPCRLIssuingPointAddCLI(CLI parent) {
        super("add", "Add OCSP CRL issuing point", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "cert-chain", true, "Path to PKCS #7 certificate chain");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "cert-format", true, "Certificate format: PEM (default), DER");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String instanceDir = CMS.getInstanceDir();
        String subsystem = parent.getParent().getParent().getName();
        String subsystemDir = instanceDir + File.separator + subsystem;
        String configFile = subsystemDir + File.separator +
                "conf" + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        OCSPEngineConfig cs = new OCSPEngineConfig(storage);
        cs.load();

        String filename = cmd.getOptionValue("cert-chain");
        byte[] bytes;
        if (filename == null) {
            logger.info("Loading certificate chain from standard input");
            bytes = IOUtils.toByteArray(System.in);

        } else {
            logger.info("Loading certificate chain from " + filename);
            bytes = Files.readAllBytes(Paths.get(filename));
        }

        String format = cmd.getOptionValue("cert-format", "PEM");
        if ("PEM".equalsIgnoreCase(format)) {
            bytes = Cert.parseCertificate(new String(bytes));

        } else if ("DER".equalsIgnoreCase(format)) {
            // nothing to do

        } else {
            throw new Exception("Unsupported format: " + format);
        }

        X509Certificate[] certs = new PKCS7(bytes).getCertificates();
        if (certs == null || certs.length == 0) {
            throw new Exception("Empty certificate chain");
        }

        // find leaf cert
        X509Certificate cert = certs[0];
        if (cert.getSubjectDN().getName().equals(cert.getIssuerDN().getName())) {
            cert = certs[certs.length - 1];
        }

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        LDAPConfig ldapConfig = dbConfig.getLDAPConfig();
        ldapConfig.putInteger("minConns", 1);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.setEngineConfig(cs);
        dbSubsystem.init(dbConfig, ldapConfig, socketConfig, passwordStore);

        OCSPConfig ocspConfig = cs.getOCSPConfig();
        String storeID = ocspConfig.getString(OCSPAuthority.PROP_DEF_STORE_ID);

        String className = ocspConfig.getString(OCSPAuthority.PROP_STORE + "." + storeID + ".class");
        ConfigStore storeConfig = ocspConfig.getSubStore(OCSPAuthority.PROP_STORE + "." + storeID, ConfigStore.class);

        IDefStore store = (IDefStore) Class.forName(className).getDeclaredConstructor().newInstance();
        store.init(storeConfig, dbSubsystem);

        // (1) need to normalize (sort) the chain
        // (2) store certificate (and certificate chain) into
        // database
        CRLIssuingPointRecord record = store.createCRLIssuingPointRecord(
                cert.getSubjectDN().getName(),
                BigInteger.ZERO,
                -1L, null, null);

        record.set(CRLIssuingPointRecord.ATTR_CA_CERT, cert.getEncoded());
        store.addCRLIssuingPoint(cert.getSubjectDN().getName(), record);
    }
}
