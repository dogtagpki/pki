// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.util.Password;

import netscape.security.pkcs.PKCS12Util;

/**
 * Tool for creating PKCS12 file
 *
 * <P>
 *
 * @version $Revision$, $Date$
 *
 */
public class PKCS12Export {

    private static Logger logger = Logger.getLogger(PKCS12Export.class.getName());

    String databaseDirectory;
    String databasePasswordFilename;

    String pkcs12PasswordFilename;
    String pkcs12OutputFilename;

    public String getDatabaseDirectory() {
        return databaseDirectory;
    }

    public void setDatabaseDirectory(String databaseDirectory) {
        this.databaseDirectory = databaseDirectory;
    }
    public String getDatabasePasswordFilename() {
        return databasePasswordFilename;
    }

    public void setDatabasePasswordFilename(String databasePasswordFilename) {
        this.databasePasswordFilename = databasePasswordFilename;
    }

    public String getPkcs12PasswordFilename() {
        return pkcs12PasswordFilename;
    }

    public void setPkcs12PasswordFilename(String pkcs12PasswordFilename) {
        this.pkcs12PasswordFilename = pkcs12PasswordFilename;
    }

    public String getPkcs12OutputFilename() {
        return pkcs12OutputFilename;
    }

    public void setPkcs12OutputFilename(String pkcs12OutputFilename) {
        this.pkcs12OutputFilename = pkcs12OutputFilename;
    }

    public void initDatabase() throws Exception {

        logger.info("Initializing database in " + databaseDirectory);

        CryptoManager.InitializationValues vals =
                new CryptoManager.InitializationValues(
                        databaseDirectory, "", "", "secmod.db");
        CryptoManager.initialize(vals);

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        logger.info("Reading database password from " + databasePasswordFilename);

        String line;
        try (BufferedReader in = new BufferedReader(new FileReader(databasePasswordFilename))) {
            line = in.readLine();
            if (line == null) {
                line = "";
            }
        }
        Password password = new Password(line.toCharArray());

        logger.info("Logging into security token");

        try {
            token.login(password);
        } finally {
            password.clear();
        }
    }

    public void exportData() throws Exception {

        logger.info("Reading PKCS #12 password from " + pkcs12PasswordFilename);

        String line;
        try (BufferedReader in = new BufferedReader(new FileReader(pkcs12PasswordFilename))) {
            line = in.readLine();
            if (line == null) {
                line = "";
            }
        }
        Password password = new Password(line.toCharArray());

        logger.info("Exporting NSS database into " + pkcs12OutputFilename);

        try {
            PKCS12Util util = new PKCS12Util();
            util.exportData(pkcs12OutputFilename, password);
        } finally {
            password.clear();
        }
    }

    public static void printUsage() {
        System.out.println(
                "Usage: PKCS12Export -d <cert/key db directory> -p <file containing password for keydb> -w <file containing pkcs12 password> -o <output file for pkcs12>");
        System.out.println();
        System.out.println("If you want to turn on debug, do the following:");
        System.out.println(
                "Usage: PKCS12Export -debug -d <cert/key db directory> -p <file containing password for keydb> -w <file containing pkcs12 password> -o <output file for pkcs12>");
    }

    public static void main(String args[]) throws Exception {

        if (args.length < 8) {
            printUsage();
            System.exit(1);
        }

        boolean debug = false;
        String databaseDirectory = null;
        String databasePasswordFilename = null;
        String pkcs12PasswordFilename = null;
        String pkcs12OutputFilename = null;

        // TODO: get parameters using getopt

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-d")) {
                databaseDirectory = args[i + 1];

            } else if (args[i].equals("-p")) {
                databasePasswordFilename = args[i + 1];

            } else if (args[i].equals("-s")) {
                // snickname = args[i + 1];

            } else if (args[i].equals("-w")) {
                pkcs12PasswordFilename = args[i + 1];

            } else if (args[i].equals("-o")) {
                pkcs12OutputFilename = args[i + 1];

            } else if (args[i].equals("-debug")) {
                debug = true;
            }
        }

        if (debug) {
            Logger.getLogger("org.dogtagpki").setLevel(Level.FINE);
            Logger.getLogger("com.netscape").setLevel(Level.FINE);
            Logger.getLogger("netscape").setLevel(Level.FINE);
        }

        // TODO: validate parameters

        try {
            PKCS12Export tool = new PKCS12Export();
            tool.setDatabaseDirectory(databaseDirectory);
            tool.setDatabasePasswordFilename(databasePasswordFilename);
            tool.setPkcs12PasswordFilename(pkcs12PasswordFilename);
            tool.setPkcs12OutputFilename(pkcs12OutputFilename);

            tool.initDatabase();
            tool.exportData();

            System.out.println("Export complete.");

        } catch (Exception e) {
            if (debug) {
                logger.log(Level.SEVERE, "Unable to export PKCS #12 file", e);
            } else {
                logger.severe("Unable to export PKCS #12 file: " + e.getMessage());
            }
            System.exit(1);
        }
    }
}
