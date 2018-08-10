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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11ECPublicKey;

import com.netscape.cmsutil.util.Utils;

import netscape.security.x509.X509CertImpl;

/**
 * Tool for verifying signed audit logs
 *
 * @version $Revision$, $Date$
 */
public class AuditVerify {

    public static final String CRYPTO_PROVIDER = "Mozilla-JSS";

    // We always sign 0x0a as the line separator, regardless of what
    // line separator characters are used in the log file. This helps
    // signature verification be platform-independent.
    private static final byte LINE_SEP_BYTE = 0x0a;

    boolean verbose;
    X509Certificate signingCert;

    public AuditVerify() {
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public void setSigningCert(X509Certificate signingCert) throws Exception {

        // verify audit signing certificate
        // not checking validity because we want to allow verifying old logs

        if (signingCert == null) {
            throw new Exception("Missing signing certificate");
        }

        byte[] bytes = signingCert.getEncoded();
        X509CertImpl cert = new X509CertImpl(bytes);

        boolean[] keyUsage = cert.getKeyUsage();

        if (keyUsage == null || keyUsage.length < 1) {
            throw new Exception("Missing signing certificate key usage");
        }

        boolean valid = keyUsage[0];

        if (!valid) {
            throw new Exception("Invalid signing certificate key usage");
        }

        this.signingCert = signingCert;
    }

    private static void usage() {
        System.out
                .println("Usage: AuditVerify -d <dbdir> -n <signing certificate nickname> -a <log list file> [-P <cert/key db prefix>] [-v]");
        System.exit(1);
    }

    public static byte[] base64decode(String input) throws Exception {
        return Utils.base64decode(input);
    }

    private static void output(int linenum, String mesg) throws IOException {
        System.out.println("Line " + linenum + ": " + mesg);
    }

    private static void writeFile(String curfileName) {
        System.out.println("======\nFile: " + curfileName + "\n======");
    }

    private static void writeSigStatus(int linenum, String sigStartFile,
            int sigStartLine, String sigStopFile, int sigStopLine, String mesg)
            throws IOException {
        output(linenum, mesg + ": signature of " + sigStartFile + ":" +
                sigStartLine + " to " + sigStopFile + ":" + sigStopLine);
    }

    private static class PrefixFilter implements FilenameFilter {
        private String prefix;

        public PrefixFilter(String prefix) {
            this.prefix = prefix;
        }

        public boolean accept(File dir, String name) {
            // look for <prefix>cert* in this directory
            return (name.indexOf(prefix + "cert") != -1);
        }
    }

    public static boolean validPrefix(String configDir, String prefix)
            throws IOException {
        File dir = new File(configDir);
        if (!dir.isDirectory()) {
            System.out.println("ERROR: \"" + dir + "\" is not a directory");
            usage();
        }

        String matchingFiles[] = dir.list(new PrefixFilter(prefix));

        // prefix may be valid if at least one file matched the pattern
        return (matchingFiles.length > 0);
    }

    public class Result {
        public int goodSigCount;
        public int badSigCount;
        public int sigStartLine;
        public int sigStopLine;
        public String sigStartFile;
        public String sigStopFile;
        public int signedLines;
    }

    public Result verify(List<String> logFiles) throws Exception {

        PublicKey pubk = signingCert.getPublicKey();

        String sigAlgorithm = null;
        if (pubk instanceof RSAPublicKey) {
            sigAlgorithm = "SHA-256/RSA";
        } else if (pubk instanceof PK11ECPublicKey) {
            sigAlgorithm = "SHA-256/EC";
        } else {
            throw new Exception("Unknown signing certificate key type: " + pubk.getAlgorithm());
        }

        if (verbose) {
            System.out.println("AuditVerify: Signing algorithm: " + sigAlgorithm);
        }

        Signature sig = Signature.getInstance(sigAlgorithm, CRYPTO_PROVIDER);

        int goodSigCount = 0;
        int badSigCount = 0;

        int lastFileWritten = -1;

        int sigStartLine = 1;
        int sigStopLine = 1;
        String sigStartFile = logFiles.get(0);
        String sigStopFile = null;
        int signedLines = 1;

        // don't start verification before the first signature
        boolean verifySignature = false;

        for (int curfile = 0; curfile < logFiles.size(); ++curfile) {

            String curfileName = logFiles.get(curfile);
            BufferedReader br = new BufferedReader(new FileReader(curfileName));

            if (verbose) {
                writeFile(curfileName);
                lastFileWritten = curfile;
            }

            String curLine;
            int linenum = 0;

            while ((curLine = br.readLine()) != null) {

                ++linenum;

                if (curLine.indexOf("AUDIT_LOG_SIGNING") != -1) { // found signature

                    if (!verifySignature) { // found first signature

                        // Ignore the first signature of the first file,
                        // since it signs data we don't have access to.
                        if (verbose) {
                            output(linenum, "Ignoring first signature of log series");
                        }

                        // start verification after the first signature
                        verifySignature = true;

                    } else { // found another signature

                        int sigStart = curLine.indexOf("sig: ");

                        if (sigStart < 0) {
                            output(linenum, "INVALID SIGNATURE");
                            ++badSigCount;

                        } else {

                            String signature = curLine.substring(sigStart + 5);

                            if (verbose) {
                                System.out.println("AuditVerify: Signature: " + signature);
                            }

                            byte[] logSig = base64decode(signature);

                            // verify the signature
                            if (sig.verify(logSig)) {

                                // signature verifies correctly
                                if (verbose) {
                                    writeSigStatus(linenum, sigStartFile,
                                            sigStartLine, sigStopFile, sigStopLine,
                                            "verification succeeded");
                                }

                                ++goodSigCount;

                            } else {

                                if (lastFileWritten < curfile) {
                                    writeFile(curfileName);
                                    lastFileWritten = curfile;
                                }

                                writeSigStatus(linenum, sigStartFile,
                                        sigStartLine, sigStopFile, sigStopLine,
                                        "VERIFICATION FAILED");

                                ++badSigCount;
                            }
                        }
                    }

                    // initialize verifier for the next signature
                    sig.initVerify(pubk);
                    signedLines = 0;
                    sigStartLine = linenum;
                    sigStartFile = curfileName;
                }

                if (verifySignature) { // update verifier only after the first signature

                    byte[] lineBytes = curLine.getBytes("UTF-8");
                    sig.update(lineBytes);
                    sig.update(LINE_SEP_BYTE);
                    ++signedLines;
                    sigStopLine = linenum;
                    sigStopFile = curfileName;
                }
            }

            br.close();
        }

        Result result = new Result();
        result.goodSigCount = goodSigCount;
        result.badSigCount = badSigCount;
        result.sigStartLine = sigStartLine;
        result.sigStopLine = sigStopLine;
        result.sigStartFile = sigStartFile;
        result.sigStopFile = sigStopFile;
        result.signedLines = signedLines;

        return result;
    }

    public static void main(String args[]) {
        try {

            String dbdir = null;
            String logListFile = null;
            String signerNick = null;
            String prefix = null;
            boolean verbose = false;

            for (int i = 0; i < args.length; ++i) {
                if (args[i].equals("-d")) {
                    if (++i >= args.length)
                        usage();
                    dbdir = args[i];
                } else if (args[i].equals("-a")) {
                    if (++i >= args.length)
                        usage();
                    logListFile = args[i];
                } else if (args[i].equals("-n")) {
                    if (++i >= args.length)
                        usage();
                    signerNick = args[i];
                } else if (args[i].equals("-P")) {
                    if (++i >= args.length)
                        usage();
                    prefix = args[i];
                } else if (args[i].equals("-v")) {
                    verbose = true;
                } else {
                    System.out.println("Unrecognized argument(" + i + "): "
                            + args[i]);
                    usage();
                }
            }
            if (dbdir == null || logListFile == null || signerNick == null) {
                System.out.println("Argument omitted");
                usage();
            }

            // get list of log files
            Vector<String> logFiles = new Vector<String>();
            BufferedReader r = new BufferedReader(new FileReader(logListFile));
            String listLine;
            while ((listLine = r.readLine()) != null) {
                StringTokenizer tok = new StringTokenizer(listLine, ",");
                while (tok.hasMoreElements()) {
                    logFiles.addElement(((String) tok.nextElement()).trim());
                }
            }
            r.close();
            if (logFiles.size() == 0) {
                System.out.println("Error: no log files listed in " + logListFile);
                System.exit(1);
            }

            // initialize crypto stuff
            if (prefix == null) {
                if (!validPrefix(dbdir, "")) {
                    System.out.println("ERROR: \"" + dbdir +
                            "\" does not contain any security databases");
                    usage();
                }
                CryptoManager.initialize(dbdir);
            } else {
                if (!validPrefix(dbdir, prefix)) {
                    System.out.println("ERROR: \"" + prefix +
                            "\" is not a valid prefix");
                    usage();
                }
                CryptoManager.initialize(
                        new CryptoManager.InitializationValues(dbdir, prefix, prefix,
                                "secmod.db")
                        );
            }

            if (verbose) {
                System.out.println("AuditVerify: Audit signing certificate: " + signerNick);
            }

            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate signerCert = cm.findCertByNickname(signerNick);

            AuditVerify verifier = new AuditVerify();
            verifier.setVerbose(verbose);
            verifier.setSigningCert(signerCert);

            Result result = verifier.verify(logFiles);

            // Make sure there were no unsigned log entries at the end.
            // The first signed line is the previous signature, but anything
            // more than that is data.
            if (result.signedLines > 1) {
                System.out.println(
                        "ERROR: log entries after " + result.sigStartFile
                                + ":" + result.sigStartLine + " are UNSIGNED");
                result.badSigCount++;
            }

            System.out.println("\nVerification process complete.");
            System.out.println("Valid signatures: " + result.goodSigCount);
            System.out.println("Invalid signatures: " + result.badSigCount);

            if (result.badSigCount > 0) {
                System.exit(2);
            } else {
                System.exit(0);
            }

        } catch (FileNotFoundException fnfe) {
            System.out.println(fnfe);
        } catch (ObjectNotFoundException onfe) {
            System.out.println("ERROR: certificate not found");
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Verification process FAILED.");
        System.exit(1);
    }
}
