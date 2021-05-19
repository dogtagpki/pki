//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.cli;

import java.io.File;
import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.server.ocsp.OCSPConfig;
import org.dogtagpki.server.ocsp.OCSPEngineConfig;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class OCSPCRLIssuingPointFindCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(OCSPCRLIssuingPointFindCLI.class);

    public OCSPCRLIssuingPointFindCLI(CLI parent) {
        super("find", "Find OCSP CRL issuing points", parent);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String s = cmd.getOptionValue("size", "100");
        int size = Integer.valueOf(s);

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String catalinaBase = System.getProperty("catalina.base");
        String subsystem = parent.getParent().getParent().getName();
        String subsystemDir = catalinaBase + File.separator + subsystem;
        String configFile = subsystemDir + File.separator +
                "conf" + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        OCSPEngineConfig engineConfig = new OCSPEngineConfig(storage);
        engineConfig.load();

        DatabaseConfig dbConfig = engineConfig.getDatabaseConfig();
        PKISocketConfig socketConfig = engineConfig.getSocketConfig();

        PasswordStoreConfig psc = engineConfig.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        DBSubsystem dbSubsystem = new DBSubsystem();
        dbSubsystem.init(dbConfig, socketConfig, passwordStore);

        OCSPConfig ocspConfig = engineConfig.getOCSPConfig();
        String storeID = ocspConfig.getString(IOCSPAuthority.PROP_DEF_STORE_ID);

        String className = ocspConfig.getString(IOCSPAuthority.PROP_STORE + "." + storeID + ".class");
        IConfigStore storeConfig = ocspConfig.getSubStore(IOCSPAuthority.PROP_STORE + "." + storeID);

        IDefStore store = (IDefStore) Class.forName(className).getDeclaredConstructor().newInstance();
        store.init(storeConfig, dbSubsystem);

        Enumeration<ICRLIssuingPointRecord> records = store.searchAllCRLIssuingPointRecord(size);
        boolean first = true;

        while (records.hasMoreElements()) {
            ICRLIssuingPointRecord record = records.nextElement();

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            System.out.println("  CRL Issuing Point ID: " + record.getId());

            X509CertImpl certImpl = new X509CertImpl(record.getCACert());
            System.out.println("  CA Subject DN: " + certImpl.getSubjectDN());
            System.out.println("  CA Issuer DN: " + certImpl.getIssuerDN());

            System.out.println("  CRL Number: " + record.getCRLNumber());
            System.out.println("  CRL Size: " + record.getCRLSize());

            System.out.println("  Delta CRL Number: " + record.getDeltaCRLNumber());
            System.out.println("  Delta CRL Size: " + record.getDeltaCRLSize());

            System.out.println("  This Update: " + record.getThisUpdate());
            System.out.println("  Next Update: " + record.getNextUpdate());

            System.out.println("  First Unsaved: " + record.getFirstUnsaved());
        }
    }
}
