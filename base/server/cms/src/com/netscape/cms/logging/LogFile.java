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
package com.netscape.cms.logging;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.CharArrayReader;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.LineNumberReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import javax.servlet.ServletException;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.Base64OutputStream;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ConsoleError;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.logging.SystemEvent;
import com.netscape.cmsutil.util.Utils;

/**
 * A log event listener which write logs to log files
 *
 * @version $Revision$, $Date$
 **/
public class LogFile implements ILogEventListener, IExtendedPluginInfo {
    public static final String PROP_TYPE = "type";
    public static final String PROP_REGISTER = "register";
    public static final String PROP_ON = "enable";
    public static final String PROP_TRACE = "trace";
    public static final String PROP_SIGNED_AUDIT_LOG_SIGNING = "logSigning";
    public static final String PROP_SIGNED_AUDIT_CERT_NICKNAME =
                              "signedAuditCertNickname";
    public static final String PROP_SIGNED_AUDIT_SELECTED_EVENTS = "events";
    public static final String PROP_SIGNED_AUDIT_UNSELECTED_EVENTS = "unselected.events";
    public static final String PROP_SIGNED_AUDIT_MANDATORY_EVENTS = "mandatory.events";
    public static final String PROP_LEVEL = "level";
    static final String PROP_FILE_NAME = "fileName";
    static final String PROP_LAST_HASH_FILE_NAME = "lastHashFileName";
    static final String PROP_BUFFER_SIZE = "bufferSize";
    static final String PROP_FLUSH_INTERVAL = "flushInterval";

    private final static String LOGGING_SIGNED_AUDIT_AUDIT_LOG_STARTUP =
                               "LOGGING_SIGNED_AUDIT_AUDIT_LOG_STARTUP_2";
    private final static String LOGGING_SIGNED_AUDIT_SIGNING =
                               "LOGGING_SIGNED_AUDIT_SIGNING_3";
    private final static String LOGGING_SIGNED_AUDIT_AUDIT_LOG_SHUTDOWN =
                               "LOGGING_SIGNED_AUDIT_AUDIT_LOG_SHUTDOWN_2";
    private final static String LOG_SIGNED_AUDIT_EXCEPTION =
                               "LOG_SIGNED_AUDIT_EXCEPTION_1";

    protected ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    protected IConfigStore mConfig = null;

    /**
     * The date string used in the log file name
     */
    static final String DATE_PATTERN = "yyyyMMddHHmmss";

    //It may be interesting to make this flexable someday....
    protected SimpleDateFormat mLogFileDateFormat = new SimpleDateFormat(DATE_PATTERN);

    /**
     * The default output stream buffer size in bytes
     */
    static final int BUFFER_SIZE = 512;

    /**
     * The default output flush interval in seconds
     */
    static final int FLUSH_INTERVAL = 5;

    /**
     * The log file
     */
    protected File mFile = null;

    /**
     * The log file name
     */
    protected String mFileName = null;

    /**
     * The log file output stream
     */
    protected BufferedWriter mLogWriter = null;

    /**
     * The log date entry format pattern
     */
    protected String mDatePattern = "dd/MMM/yyyy:HH:mm:ss z";

    /**
     * The log date entry format
     */
    protected SimpleDateFormat mLogDateFormat = new SimpleDateFormat(mDatePattern);

    /**
     * The date object used for log entries
     */
    protected Date mDate = new Date();

    /**
     * The number of bytes written to the current log file
     */
    protected int mBytesWritten = 0;

    /**
     * The output buffer size in bytes
     */
    protected int mBufferSize = BUFFER_SIZE;

    /**
     * The output buffer flush interval
     */
    protected int mFlushInterval = FLUSH_INTERVAL;

    /**
     * The number of unflushed bytes
     */
    protected int mBytesUnflushed = 0;

    /**
     * The output buffer flush interval thread
     */
    private Thread mFlushThread = null;

    /**
     * The mandatory log event types
     */
    protected Set<String> mandatoryEvents = new LinkedHashSet<String>();

    /**
     * The selected log event types
     */
    protected Set<String> selectedEvents = new LinkedHashSet<String>();

    /**
     * The unselected log event types
     */
    protected Set<String> unselectedEvents = new LinkedHashSet<String>();

    /**
     * The eventType that this log is triggered
     */
    protected String mType = null;

    /**
     * The log is turned on/off
     */
    protected boolean mOn = false;

    /**
     * Should this log listener self-register or not
     */
    protected boolean mRegister = false;

    protected boolean mTrace = false;

    /**
     * Log signing is on/off
     */
    protected boolean mLogSigning = false;

    /**
     * Nickname of certificate to use to sign log.
     */
    private String mSAuditCertNickName = "";

    /**
     * The provider used by the KeyGenerator and Mac
     */
    static final String CRYPTO_PROVIDER = "Mozilla-JSS";

    /**
     * The log level threshold
     * Only logs with level greater or equal than this value will be written
     */
    protected long mLevel = 1;

    /**
     * Constructor for a LogFile.
     *
     */
    public LogFile() {
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;

        try {
            mOn = config.getBoolean(PROP_ON, true);
        } catch (EBaseException e) {
            throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_ON));
        }

        try {
            mLogSigning = config.getBoolean(PROP_SIGNED_AUDIT_LOG_SIGNING,
                                            false);
        } catch (EBaseException e) {
            throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_SIGNED_AUDIT_LOG_SIGNING));
        }

        if (mOn && mLogSigning) {
            try {
                mSAuditCertNickName = config.getString(
                                          PROP_SIGNED_AUDIT_CERT_NICKNAME);
                CMS.debug("LogFile: init(): audit log signing enabled. signedAuditCertNickname=" + mSAuditCertNickName);
            } catch (EBaseException e) {
                throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                        config.getName() + "."
                                         + PROP_SIGNED_AUDIT_CERT_NICKNAME));
            }
            if (mSAuditCertNickName == null ||
                    mSAuditCertNickName.trim().equals("")) {
                throw new ELogException(CMS.getUserMessage(
                        "CMS_BASE_GET_PROPERTY_FAILED",
                        config.getName() + "."
                                + PROP_SIGNED_AUDIT_CERT_NICKNAME));
            }
        }

        // mandatory events
        String mandatoryEventsList = config.getString(PROP_SIGNED_AUDIT_MANDATORY_EVENTS, "");
        for (String event : StringUtils.split(mandatoryEventsList, ", ")) {
            mandatoryEvents.add(event);
        }

        // selected events
        String selectedEventsList = config.getString(PROP_SIGNED_AUDIT_SELECTED_EVENTS, "");
        for (String event : StringUtils.split(selectedEventsList, ", ")) {
            selectedEvents.add(event);
        }

        // unselected events
        String unselectedEventsList = config.getString(PROP_SIGNED_AUDIT_UNSELECTED_EVENTS, "");
        for (String event : StringUtils.split(unselectedEventsList, ", ")) {
            unselectedEvents.add(event);
        }

        try {
            init(config);
        } catch (IOException e) {
            throw new ELogException(CMS.getUserMessage("CMS_LOG_UNEXPECTED_EXCEPTION", e.toString()));
        }
    }

    /**
     * add the event to the selected events list
     *
     * @param event to be selected
     */
    public void selectEvent(String event) {
        selectedEvents.add(event);
        unselectedEvents.remove(event);
    }

    /**
     * remove the event from the selected events list
     *
     * @param event to be de-selected
     */
    public void deselectEvent(String event) {
        selectedEvents.remove(event);
        unselectedEvents.add(event);
    }

    /**
     * replace the selected events list
     *
     * @param events comma-separated event list
     */
    public void replaceEvents(String events) {
        // unselect all events
        unselectedEvents.addAll(selectedEvents);
        selectedEvents.clear();

        // select specified events
        for (String event : StringUtils.split(events, ", ")) {
            selectEvent(event);
        }
    }

    public static String base64Encode(byte[] bytes) throws IOException {
        // All this streaming is lame, but Base64OutputStream needs a
        // PrintStream
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (Base64OutputStream b64 = new Base64OutputStream(
                new PrintStream(new FilterOutputStream(output)))) {
            b64.write(bytes);
            b64.flush();

            // This is internationally safe because Base64 chars are
            // contained within 8859_1
            return output.toString("8859_1");
        }
    }

    private static boolean mInSignedAuditLogFailureMode = false;

    private static synchronized void shutdownCMS() {
        if (mInSignedAuditLogFailureMode == false) {

            // Set signed audit log failure mode true
            // No, this isn't a race condition, because the method is
            // synchronized. We just want to avoid an infinite loop.
            mInSignedAuditLogFailureMode = true;

            // Block all new incoming requests
            if (CMS.areRequestsDisabled() == false) {
                // XXX is this a race condition?
                CMS.disableRequests();
            }

            // Terminate all requests in process
            CMS.terminateRequests();

            // Call graceful shutdown of the CMS server
            // Call force shutdown to get added functionality of
            // making sure to kill the web server.

            CMS.forceShutdown();
        }
    }

    /**
     * Initialize and open the log using the parameters from a config store
     *
     * @param config The property config store to find values in
     */
    public void init(IConfigStore config) throws IOException,
            EBaseException {
        String fileName = null;
        String defaultFileName = null;
        String signedAuditDefaultFileName = "";

        mConfig = config;

        try {
            mTrace = config.getBoolean(PROP_TRACE, false);
        } catch (EBaseException e) {
            throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_TRACE));
        }

        try {
            mType = config.getString(PROP_TYPE, "system");
        } catch (EBaseException e) {
            throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_TYPE));
        }

        try {
            mRegister = config.getBoolean(PROP_REGISTER, true);
        } catch (EBaseException e) {
            throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_REGISTER));
        }

        if (mOn) {
            if (mRegister) {
                CMS.getLogger().getLogQueue().addLogEventListener(this);
            }
        } else {
            // shutdown the listener, remove the listener
            if (mRegister) {
                CMS.getLogger().getLogQueue().removeLogEventListener(this);
                shutdown();
            }
        }

        try {
            mLevel = config.getInteger(PROP_LEVEL, 3);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_LEVEL));
        }

        try {
            // retrieve the subsystem
            String subsystem = "";

            ISubsystem caSubsystem = CMS.getSubsystem("ca");
            if (caSubsystem != null) {
                subsystem = "ca";
            }

            ISubsystem raSubsystem = CMS.getSubsystem("ra");
            if (raSubsystem != null) {
                subsystem = "ra";
            }

            ISubsystem kraSubsystem = CMS.getSubsystem("kra");
            if (kraSubsystem != null) {
                subsystem = "kra";
            }

            ISubsystem ocspSubsystem = CMS.getSubsystem("ocsp");
            if (ocspSubsystem != null) {
                subsystem = "ocsp";
            }

            // retrieve the instance name
            String instIDPath = CMS.getInstanceDir();
            int index = instIDPath.lastIndexOf("/");
            String instID = instIDPath.substring(index + 1);

            // build the default signedAudit file name
            signedAuditDefaultFileName = subsystem + "_"
                                       + instID + "_" + "audit";

        } catch (Exception e2) {
            throw new ELogException(
                          CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                                              config.getName() + "." +
                                                      PROP_FILE_NAME));
        }

        // the default value is determined by the eventType.
        if (mType.equals(ILogger.PROP_SIGNED_AUDIT)) {
            defaultFileName = "logs/signedAudit/" + signedAuditDefaultFileName;
        } else if (mType.equals(ILogger.PROP_SYSTEM)) {
            defaultFileName = "logs/system";
        } else if (mType.equals(ILogger.PROP_AUDIT)) {
            defaultFileName = "logs/transactions";
        } else {
            //wont get here
            throw new ELogException(CMS.getUserMessage("CMS_LOG_INVALID_LOG_TYPE",
                    config.getName()));
        }

        try {
            fileName = config.getString(PROP_FILE_NAME, defaultFileName);
        } catch (EBaseException e) {
            throw new ELogException(CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_FILE_NAME));
        }

        if (mOn) {
            init(fileName, config.getInteger(PROP_BUFFER_SIZE, BUFFER_SIZE),
                    config.getInteger(PROP_FLUSH_INTERVAL, FLUSH_INTERVAL));
        }
    }

    /**
     * Initialize and open the log
     *
     * @param bufferSize The buffer size for the output stream in bytes
     * @param flushInterval The interval in seconds to flush the log
     */
    public void init(String fileName, int bufferSize, int flushInterval) throws IOException, ELogException {

        if (fileName == null)
            throw new ELogException(CMS.getUserMessage("CMS_LOG_INVALID_FILE_NAME", "null"));

        //If we want to reuse the old log files
        //mFileName = fileName + "." + mLogFileDateFormat.format(mDate);
        mFileName = fileName;
        if (!Utils.isNT()) {
            // Always insure that a physical file exists!
            Utils.exec("touch " + mFileName);
            Utils.exec("chmod 00640 " + mFileName);
        }
        mFile = new File(mFileName);
        mBufferSize = bufferSize;
        setFlushInterval(flushInterval);
        open();
    }

    private PrivateKey mSigningKey = null;
    private Signature mSignature = null;

    private void setupSigning() throws EBaseException {
        try {

            Provider[] providers = java.security.Security.getProviders();
            int ps = providers.length;
            for (int i = 0; i < ps; i++) {
                CMS.debug("LogFile: provider " + i + "= " + providers[i].getName());
            }

            CryptoManager cm = CryptoManager.getInstance();

            // find CertServer's private key
            X509Certificate cert = cm.findCertByNickname(mSAuditCertNickName);
            if (cert != null) {
                CMS.debug("LogFile: setupSignig(): found cert:" + mSAuditCertNickName);
            } else {
                CMS.debug("LogFile: setupSignig(): cert not found:" + mSAuditCertNickName);
            }
            mSigningKey = cm.findPrivKeyByCert(cert);

            String sigAlgorithm;
            if (mSigningKey instanceof RSAPrivateKey) {
                sigAlgorithm = "SHA-256/RSA";
            } else if (mSigningKey instanceof DSAPrivateKey) {
                sigAlgorithm = "SHA-256/DSA";
            } else {
                throw new NoSuchAlgorithmException("Unknown private key type");
            }

            CryptoToken savedToken = cm.getThreadToken();
            try {
                CryptoToken keyToken =
                        ((org.mozilla.jss.pkcs11.PK11PrivKey) mSigningKey)
                                .getOwningToken();
                cm.setThreadToken(keyToken);
                mSignature = java.security.Signature.getInstance(sigAlgorithm,
                        CRYPTO_PROVIDER);
            } finally {
                cm.setThreadToken(savedToken);
            }

            mSignature.initSign(mSigningKey);

            // get the last signature from the currently-opened file
            String entry = getLastSignature(mFile);
            if (entry != null) {
                mSignature.update(entry.getBytes("UTF-8"));
                mSignature.update(LINE_SEP_BYTE);
            }

            // Always start off with a signature. That way, even if there
            // were problems with the log file we inherited, we will
            // get a fresh start with this instance.
            pushSignature();

        } catch (CryptoManager.NotInitializedException nie) {
            setupSigningFailure("BASE_CRYPTOMANAGER_UNINITIALIZED", nie);
        } catch (ObjectNotFoundException onfe) {
            setupSigningFailure("LOG_SIGNING_CERT_NOT_FOUND", onfe);
        } catch (TokenException te) {
            setupSigningFailure("BASE_TOKEN_ERROR_0", te);
        } catch (NoSuchAlgorithmException nsae) {
            setupSigningFailure("LOG_NO_SUCH_ALGORITHM_0", nsae);
        } catch (NoSuchProviderException nspe) {
            setupSigningFailure("BASE_PROVIDER_NOT_SUPPORTED", nspe);
        } catch (InvalidKeyException ike) {
            setupSigningFailure("BASE_INVALID_KEY", ike);
        } catch (SignatureException se) {
            setupSigningFailure("LOG_SIGNING_OP_FAILED", se);
        } catch (UnsupportedEncodingException uee) {
            setupSigningFailure("LOG_UNEXPECTED_EXCEPTION", uee);
        } catch (IOException ioe) {
            setupSigningFailure("LOG_UNEXPECTED_EXCEPTION", ioe);
        } catch (Exception e) {
            setupSigningFailure("LOG_UNEXPECTED_EXCEPTION", e);
        }
    }

    private static void setupSigningFailure(String logMessageCode, Exception e)
            throws EBaseException {
        try {
            ConsoleError.send(new SystemEvent(
                    CMS.getLogMessage(logMessageCode)));
        } catch (Exception e2) {
            // don't allow an exception while printing to the console
            // prevent us from running the rest of this function.
            e2.printStackTrace();
        }
        e.printStackTrace();
        shutdownCMS();
        throw new EBaseException(e.toString());
    }

    /**
     * Startup the instance
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUDIT_LOG_STARTUP used at audit function startup
     * </ul>
     *
     * @exception EBaseException if an internal error occurred
     */
    public void startup() throws EBaseException {
        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        CMS.debug("LogFile: entering LogFile.startup()");
        if (mOn && mLogSigning) {
            try {
                setupSigning();
                audit(CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUDIT_LOG_STARTUP,
                        ILogger.SYSTEM_UID,
                        ILogger.SUCCESS));
            } catch (EBaseException e) {
                audit(CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUDIT_LOG_STARTUP,
                        ILogger.SYSTEM_UID,
                        ILogger.FAILURE));
                throw e;
            }
        }

    }

    /**
     * Retrieves the eventType this log is triggered.
     */
    public String getType() {
        return mType;
    }

    /**
     * Retrieves the log on/off.
     */
    public String getOn() {
        return String.valueOf(mOn);
    }

    /**
     * Retrieves the log level threshold.
     */
    public long getLevel() {
        return mLevel;
    }

    /**
     * Retrieves the base log file name.
     */
    public String getName() {
        return mFileName;
    }

    /**
     * Record that the signed audit log has been signed
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_SIGNING used when a signature on the audit log is generated (same as
     * "flush" time)
     * </ul>
     *
     * @exception IOException for input/output problems
     * @exception ELogException when plugin implementation fails
     * @exception SignatureException when signing fails
     * @exception InvalidKeyException when an invalid key is utilized
     */
    private void pushSignature() throws IOException, ELogException,
            SignatureException, InvalidKeyException {
        byte[] sigBytes = null;

        if (mSignature == null) {
            return;
        }

        sigBytes = mSignature.sign();
        mSignature.initSign(mSigningKey);

        Object o[] = new Object[1];
        o[0] = null;

        // cook up a signed audit log message to record mac
        // so as to avoid infinite recursiveness of calling
        // the log() method
        String auditMessage = CMS.getLogMessage(
                LOGGING_SIGNED_AUDIT_SIGNING,
                ILogger.SYSTEM_UID,
                ILogger.SUCCESS,
                base64Encode(sigBytes));

        if (mSignedAuditLogger == null) {
            return;
        }

        ILogEvent ev = mSignedAuditLogger.create(
                ILogger.EV_SIGNED_AUDIT,
                (Properties) null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                auditMessage,
                o,
                ILogger.L_SINGLELINE);

        String logMesg = logEvt2String(ev);
        doLog(logMesg, true);
    }

    private static String getLastSignature(File f) throws IOException {
        BufferedReader r = new BufferedReader(new FileReader(f));
        String lastSig = null;
        String curLine = null;
        while ((curLine = r.readLine()) != null) {
            if (curLine.indexOf("AUDIT_LOG_SIGNING") != -1) {
                lastSig = curLine;
            }
        }
        r.close();
        return lastSig;
    }

    /**
     * Open the log file. This creates the buffered FileWriter
     *
     */
    protected synchronized void open() throws IOException {
        RandomAccessFile out;

        try {
            out = new RandomAccessFile(mFile, "rw");
            out.seek(out.length());
            //XXX int or long?
            mBytesWritten = (int) out.length();
            if (!Utils.isNT()) {
                try {
                    Utils.exec("chmod 00640 " + mFile.getCanonicalPath());
                } catch (IOException e) {
                    CMS.debug("Unable to change file permissions on "
                             + mFile.toString());
                }
            }
            mLogWriter = new BufferedWriter(
                        new FileWriter(out.getFD()), mBufferSize);

            // The first time we open, mSignature will not have been
            // initialized yet. That's ok, we will push our first signature
            // in setupSigning().
            if (mLogSigning && (mSignature != null)) {
                try {
                    pushSignature();
                } catch (ELogException le) {
                    ConsoleError.send(
                            new SystemEvent(CMS.getUserMessage("CMS_LOG_ILLEGALARGUMENT",
                                    mFileName)));
                }
            }
        } catch (IllegalArgumentException iae) {
            ConsoleError.send(
                    new SystemEvent(CMS.getUserMessage("CMS_LOG_ILLEGALARGUMENT",
                            mFileName)));
        } catch (GeneralSecurityException gse) {
            // error with signed audit log, shutdown CMS
            gse.printStackTrace();
            shutdownCMS();
        }

        mBytesUnflushed = 0;
    }

    /**
     * Flush the log file. Also update the MAC for hash protected logs
     *
     */
    public synchronized void flush() {
        try {
            if (mLogSigning) {
                try {
                    pushSignature();
                } catch (ELogException le) {
                    ConsoleError.send(new SystemEvent(CMS.getUserMessage("CMS_LOG_FLUSH_LOG_FAILED", mFileName,
                            le.toString())));
                }
            }

            if (mLogWriter != null) {
                mLogWriter.flush();
            }
        } catch (IOException e) {
            ConsoleError.send(new SystemEvent(CMS.getUserMessage("CMS_LOG_FLUSH_LOG_FAILED", mFileName, e.toString())));
            if (mLogSigning) {
                //error in writing to signed audit log, shut down CMS
                e.printStackTrace();
                shutdownCMS();
            }
        } catch (GeneralSecurityException gse) {
            // error with signed audit log, shutdown CMS
            gse.printStackTrace();
            shutdownCMS();
        }

        mBytesUnflushed = 0;
    }

    /**
     * Close the log file
     *
     */
    protected synchronized void close() {
        try {
            flush();
            if (mLogWriter != null) {
                mLogWriter.close();
            }
        } catch (IOException e) {
            ConsoleError.send(new SystemEvent(CMS.getUserMessage("CMS_LOG_CLOSE_FAILED", mFileName, e.toString())));
        }
        mLogWriter = null;
    }

    /**
     * Shutdown this log file.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUDIT_LOG_SHUTDOWN used at audit function shutdown
     * </ul>
     */
    public synchronized void shutdown() {
        String auditMessage = null;

        CMS.debug("LogFile:In log shutdown");

        setFlushInterval(0);

        // log signed audit shutdown success
        auditMessage = CMS.getLogMessage(
                           LOGGING_SIGNED_AUDIT_AUDIT_LOG_SHUTDOWN,
                           ILogger.SYSTEM_UID,
                           ILogger.SUCCESS);

        audit(auditMessage);

        close();
    }

    /**
     * Set the flush interval
     * <P>
     *
     * @param flushInterval The amount of time in seconds until the log
     *            is flush. A value of 0 will disable autoflush. This will also set
     *            the update period for hash protected logs.
     **/
    public synchronized void setFlushInterval(int flushInterval) {
        mFlushInterval = flushInterval * 1000;

        if ((mFlushThread == null) && (mFlushInterval > 0)) {
            mFlushThread = new FlushThread();
            mFlushThread.setDaemon(true);
            mFlushThread.start();
        }

        this.notify();
    }

    /**
     * Log flush thread. Sleep for the flush interval and flush the
     * log. Changing flush interval to 0 will cause this thread to exit.
     */
    final class FlushThread extends Thread {

        /**
         * Flush thread constructor including thread name
         */
        public FlushThread() {
            super();
            super.setName(mFileName + ".flush-" + (Thread.activeCount() + 1));
        }

        public void run() {
            while (mFlushInterval > 0) {
                // Sleep for the interval and then flush the log
                synchronized (LogFile.this) {
                    try {
                        LogFile.this.wait(mFlushInterval);
                    } catch (InterruptedException e) {
                        // This shouldn't happen very often
                        ConsoleError.send(new
                                SystemEvent(CMS.getUserMessage("CMS_LOG_THREAD_INTERRUPT", "flush")));
                    }
                }

                if (mFlushInterval == 0) {
                    break;
                }

                if (mBytesUnflushed > 0) {
                    flush();
                }
            }
            mFlushThread = null;
        }
    }

    /**
     * Synchronized method to write a string to the log file. All I18N
     * should take place before this call.
     *
     * @param entry The log entry string
     */
    protected synchronized void log(String entry) throws ELogException {
        doLog(entry, false);
    }

    // Standard line separator byte. We always sign this line separator,
    // regardless of what we actually write to the file, so that signature
    // verification is platform-independent.
    private static final byte LINE_SEP_BYTE = 0x0a;

    /**
     * This method actually does the logging, and is not overridden
     * by subclasses, so you can call it and know that it will do exactly
     * what you see below.
     */
    private synchronized void doLog(String entry, boolean noFlush)
            throws ELogException {
        if (mLogWriter == null) {
            String[] params = { mFileName, entry };

            throw new ELogException(CMS.getUserMessage("CMS_LOG_LOGFILE_CLOSED", params));
        } else {
            try {
                mLogWriter.write(entry, 0/*offset*/, entry.length());

                if (mLogSigning == true) {
                    if (mSignature != null) {
                        // include newline for calculating MAC
                        mSignature.update(entry.getBytes("UTF-8"));
                    } else {
                        CMS.debug("LogFile: mSignature is not yet ready... null in log()");
                    }
                }
                if (mTrace) {
                    CharArrayWriter cw = new CharArrayWriter(200);
                    PrintWriter pw = new PrintWriter(cw);
                    Exception e = new Exception();
                    e.printStackTrace(pw);
                    char[] c = cw.toCharArray();
                    cw.close();
                    pw.close();

                    CharArrayReader cr = new CharArrayReader(c);
                    LineNumberReader lr = new LineNumberReader(cr);

                    String text = null;
                    String method = null;
                    String fileAndLine = null;
                    if (lr.ready()) {
                        text = lr.readLine();
                        do {
                            text = lr.readLine();
                        } while (text.indexOf("logging") != -1);
                        int p = text.indexOf("(");
                        fileAndLine = text.substring(p);

                        String classandmethod = text.substring(0, p);
                        int q = classandmethod.lastIndexOf(".");
                        method = classandmethod.substring(q + 1);
                        mLogWriter.write(fileAndLine, 0/*offset*/, fileAndLine.length());
                        mLogWriter.write(" ", 0/*offset*/, " ".length());
                        mLogWriter.write(method, 0/*offset*/, method.length());
                    }
                }
                mLogWriter.newLine();

                if (mLogSigning == true) {
                    if (mSignature != null) {
                        mSignature.update(LINE_SEP_BYTE);
                    } else {
                        CMS.debug("LogFile: mSignature is null in log() 2");
                    }
                }
            } catch (IOException e) {
                ConsoleError.send(new SystemEvent(CMS.getUserMessage("CMS_LOG_WRITE_FAILED", mFileName, entry,
                        e.toString())));
                if (mLogSigning) {
                    // Failed to write to audit log, shut down CMS
                    e.printStackTrace();
                    shutdownCMS();
                }
            } catch (IllegalStateException e) {
                CMS.debug("LogFile: exception thrown in log(): " + e.toString());
                ConsoleError.send(new SignedAuditEvent(CMS.getLogMessage(LOG_SIGNED_AUDIT_EXCEPTION, e.toString())));
            } catch (GeneralSecurityException gse) {
                // DJN: handle error
                CMS.debug("LogFile: exception thrown in log(): "
                        + gse.toString());
                gse.printStackTrace();
                ConsoleError.send(new SignedAuditEvent(CMS.getLogMessage(
                        LOG_SIGNED_AUDIT_EXCEPTION, gse.toString())));
            }

            // XXX
            // Although length will be in Unicode dual-bytes, the PrintWriter
            // will only print out 1 byte per character.  I suppose this could
            // be dependent on the encoding of your log file, but it ain't that
            // smart yet.  Also, add one for the newline. (hmm, on NT, CR+LF)
            int nBytes = entry.length() + 1;

            mBytesWritten += nBytes;
            mBytesUnflushed += nBytes;

            if (mBufferSize > 0 && mBytesUnflushed > mBufferSize && !noFlush) {
                flush();
            }
        }
    }

    /**
     * Write an event to the log file
     *
     * @param ev The event to be logged.
     */
    public void log(ILogEvent ev) throws ELogException {
        if (ev instanceof AuditEvent) {
            if (!mType.equals("transaction") || (!mOn) || mLevel > ev.getLevel()) {
                return;
            }
        } else if (ev instanceof SystemEvent) {
            if (!mType.equals("system") || (!mOn) || mLevel > ev.getLevel()) {
                return;
            }
        } else if (ev instanceof SignedAuditEvent) {
            if (!mType.equals("signedAudit") || (!mOn) || mLevel > ev.getLevel()) {
                return;
            }
        }

        // If no selection specified in configuration, then all are selected
        if (selectedEvents.isEmpty()) {
            String entry = logEvt2String(ev);
            log(entry);
            return;
        }

        // If no type specified in propertity file, then treated as selected
        String type = ev.getEventType();
        if (type == null) {
            String entry = logEvt2String(ev);
            log(entry);
            return;
        }

        // Is the event type mandatory or selected?
        if (mandatoryEvents.contains(type) || selectedEvents.contains(type)) {
            String entry = logEvt2String(ev);
            log(entry);
            return;
        }

        CMS.debug("LogFile: event type not selected: " + type);
    }

    public String logEvt2String(ILogEvent ev) {
        String entry = null;

        // Hmm.. multiple threads could hit this and reset the time.
        // Do we care?
        mDate.setTime(ev.getTimeStamp());

        // XXX
        // This should follow the Common Log Format which still needs
        // some work.
        if (ev.getMultiline() == ILogger.L_MULTILINE) {
            entry = CMS.getPID() + "." + Thread.currentThread().getName() + " - ["
                    + mLogDateFormat.format(mDate) + "] [" +
                    Integer.toString(ev.getSource()) + "] [" + Integer.toString(ev.getLevel())
                    + "] " + prepareMultiline(ev.toString());
        } else {
            entry = CMS.getPID() + "." + Thread.currentThread().getName() + " - ["
                    + mLogDateFormat.format(mDate) + "] [" +
                    Integer.toString(ev.getSource()) + "] [" + Integer.toString(ev.getLevel())
                    + "] " + ev.toString();
        }

        return entry;
    }

    /**
     * change multi-line log entry by replace "\n" with "\n "
     *
     * @param original The original multi-line log entry.
     */
    private String prepareMultiline(String original) {
        int i, last = 0;

        //NT: \r\n, unix: \n
        while ((i = original.indexOf("\n", last)) != -1) {
            last = i + 1;
            original = original.substring(0, i + 1) + " " + original.substring(i + 1);
        }
        return original;
    }

    /**
     * Read all entries whose logLevel>=lowLevel && log source = source
     * to at most maxLine entries(from end)
     * If the parameter is -1, it's ignored and return all entries
     *
     * @param maxLine The maximum lines to be returned
     * @param lowLevel The lowest log level to be returned
     * @param source The particular log source to be returned
     * @param fName The log file name to be read. If it's null, read the current
     *            log file
     */
    public Vector<LogEntry> readEntry(int maxLine, int lowLevel, int source, String fName) {
        Vector<LogEntry> mEntries = new Vector<LogEntry>();
        String fileName = mFileName;
        BufferedReader fBuffer;
        int lineNo = 0; // lineNo of the current entry in the log file
        int line = 0; // line of readed valid entries
        String firstLine = null; // line buffer
        String nextLine = null;
        String entry = null;
        LogEntry logEntry = null;

        /*
         this variable is added to accormodate misplaced multiline entries
         write out buffered log entry when next entry is parsed successfully
         this implementation is assuming parsing is more time consuming than
         condition check
         */
        LogEntry preLogEntry = null;

        if (fName != null) {
            fileName = fName;
        }
        try {
            //XXX think about this
            fBuffer = new BufferedReader(new FileReader(fileName));
            do {
                try {
                    nextLine = fBuffer.readLine();
                    if (nextLine != null) {
                        if ((nextLine.length() == 0) || (nextLine.charAt(0) == ' ')) {
                            // It's a continuous line
                            entry = null;
                            if (nextLine.length() > 1)
                                firstLine = firstLine + "\n" + nextLine.substring(1);
                            else
                                firstLine = firstLine + "\n";

                        } else {
                            // It's a new entry
                            entry = firstLine;
                            firstLine = nextLine;
                        }
                        // parse the previous entry, the current one is buffered
                        if (entry != null) {
                            try {
                                logEntry = new LogEntry(entry);
                                // if parse succeed, write out previous entry
                                if (preLogEntry != null) {
                                    if ((Integer.parseInt(preLogEntry.getLevel()) >= lowLevel) &&
                                            ((Integer.parseInt(preLogEntry.getSource()) == source) ||
                                            (source == ILogger.S_ALL)
                                            )) {
                                        mEntries.addElement(preLogEntry);
                                        if (maxLine == -1) {
                                            line++;
                                        } else if (line < maxLine) {
                                            line++;
                                        } else {
                                            mEntries.removeElementAt(0);
                                        }
                                    }
                                }
                                preLogEntry = logEntry;
                            } catch (ParseException e) {
                                if (preLogEntry != null) {
                                    preLogEntry.appendDetail(entry);
                                } else {
                                    firstLine = firstLine + "\n" + nextLine;
                                }
                                entry = null;
                                logEntry = null;
                            }
                        }
                    }
                    lineNo++;

                } catch (IOException e) {
                    CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                            ILogger.LL_FAILURE,
                            CMS.getLogMessage("LOGGING_READ_ERROR", fileName,
                                    Integer.toString(lineNo)));
                }

            } while (nextLine != null);

            // need to process the last 2 entries of the file
            if (firstLine != null) {
                if (logEntry != null) {
                    preLogEntry = logEntry;
                }
                entry = firstLine;
                try {
                    logEntry = new LogEntry(entry);

                    /*  System.out.println(
                     Integer.toString(Integer.parseInt(logEntry.getLevel()))
                     +","+Integer.toString(lowLevel)+","+
                     Integer.toString(Integer.parseInt(logEntry.getSource()))
                     +","+Integer.toString(source) );
                     */
                    if (preLogEntry != null) {
                        if ((Integer.parseInt(preLogEntry.getLevel()) >= lowLevel) &&
                                ((Integer.parseInt(preLogEntry.getSource()) == source) ||
                                (source == ILogger.S_ALL)
                                )) {
                            mEntries.addElement(preLogEntry);
                            if (maxLine == -1) {
                                line++;
                            } else if (line < maxLine) {
                                line++;
                            } else {
                                mEntries.removeElementAt(0);
                            }
                        }
                    }
                    preLogEntry = logEntry;
                } catch (ParseException e) {
                    preLogEntry.appendDetail(entry);
                }

                if (preLogEntry != null) {
                    if ((Integer.parseInt(preLogEntry.getLevel()) >= lowLevel)
                            &&
                            ((Integer.parseInt(preLogEntry.getSource()) == source)
                            ||
                            (source == ILogger.S_ALL)
                            )) {
                        // parse the entry, pass to UI
                        mEntries.addElement(preLogEntry);
                        if (maxLine == -1) {
                            line++;
                        } else if (line < maxLine) {
                            line++;
                        } else {
                            mEntries.removeElementAt(0);
                        }
                    }
                }

            }// end: last entry

            try {
                fBuffer.close();
            } catch (IOException e) {
                CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                        ILogger.LL_FAILURE, "logging:" + fileName +
                                " failed to close for reading");
            }

        } catch (FileNotFoundException e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE,
                    CMS.getLogMessage("LOGGING_FILE_NOT_FOUND",
                            fileName));
        }
        return mEntries;
    }

    /**
     * Retrieves the configuration store of this subsystem.
     * <P>
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieve last "maxLine" number of system log with log lever >"level"
     * and from source "source". If the parameter is omitted. All entries
     * are sent back.
     */
    public synchronized NameValuePairs retrieveLogContent(Hashtable<String, String> req) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        String tmp, fName = null;
        int maxLine = -1, level = -1, source = -1;
        Vector<LogEntry> entries = null;

        if ((tmp = req.get(Constants.PR_LOG_ENTRY)) != null) {
            maxLine = Integer.parseInt(tmp);
        }
        if ((tmp = req.get(Constants.PR_LOG_LEVEL)) != null) {
            level = Integer.parseInt(tmp);
        }
        if ((tmp = req.get(Constants.PR_LOG_SOURCE)) != null) {
            source = Integer.parseInt(tmp);
        }
        tmp = req.get(Constants.PR_LOG_NAME);
        if (!(tmp.equals(Constants.PR_CURRENT_LOG))) {
            fName = tmp;
        } else {
            flush();
        }

        try {
            entries = readEntry(maxLine, level, source, fName);
            for (int i = 0; i < entries.size(); i++) {
                params.put(Integer.toString(i) +
                        entries.elementAt(i).getEntry(), "");
            }
        } catch (Exception e) {
            CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_WARN,
                    "System log parse error");
        }
        return params;
    }

    /**
     * Retrieve log file list.
     */
    public synchronized NameValuePairs retrieveLogList(Hashtable<String, String> req) throws ServletException,
            IOException, EBaseException {
        return null;
    }

    public String getImplName() {
        return "LogFile";
    }

    public String getDescription() {
        return "LogFile";
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<String>();

        v.addElement(PROP_TYPE + "=");
        v.addElement(PROP_ON + "=");
        v.addElement(PROP_LEVEL + "=");
        v.addElement(PROP_FILE_NAME + "=");
        v.addElement(PROP_BUFFER_SIZE + "=");
        v.addElement(PROP_FLUSH_INTERVAL + "=");

        // needs to find a way to determine what type you want. if this
        // is not for the signed audit type, then we should not show the
        // following parameters.
        //if( mType.equals( ILogger.PROP_SIGNED_AUDIT ) ) {
        v.addElement(PROP_SIGNED_AUDIT_LOG_SIGNING + "=");
        v.addElement(PROP_SIGNED_AUDIT_CERT_NICKNAME + "=");
        v.addElement(PROP_SIGNED_AUDIT_MANDATORY_EVENTS + "=");
        v.addElement(PROP_SIGNED_AUDIT_SELECTED_EVENTS + "=");
        v.addElement(PROP_SIGNED_AUDIT_UNSELECTED_EVENTS + "=");
        //}

        return v;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = new Vector<String>();

        try {

            if (mType == null) {
                v.addElement(PROP_TYPE + "=");
            } else {
                v.addElement(PROP_TYPE + "=" +
                        mConfig.getString(PROP_TYPE));
            }
            v.addElement(PROP_ON + "=" + String.valueOf(mOn));
            if (mLevel == 0)
                v.addElement(PROP_LEVEL + "=" + ILogger.LL_DEBUG_STRING);
            else if (mLevel == 1)
                v.addElement(PROP_LEVEL + "=" + ILogger.LL_INFO_STRING);
            else if (mLevel == 2)
                v.addElement(PROP_LEVEL + "=" + ILogger.LL_WARN_STRING);
            else if (mLevel == 3)
                v.addElement(PROP_LEVEL + "=" + ILogger.LL_FAILURE_STRING);
            else if (mLevel == 4)
                v.addElement(PROP_LEVEL + "=" + ILogger.LL_MISCONF_STRING);
            else if (mLevel == 5)
                v.addElement(PROP_LEVEL + "=" + ILogger.LL_CATASTRPHE_STRING);
            else if (mLevel == 6)
                v.addElement(PROP_LEVEL + "=" + ILogger.LL_SECURITY_STRING);

            if (mFileName == null) {
                v.addElement(PROP_FILE_NAME + "=");
            } else {
                v.addElement(PROP_FILE_NAME + "=" +
                        mFileName);
            }
            v.addElement(PROP_BUFFER_SIZE + "=" + mBufferSize);
            v.addElement(PROP_FLUSH_INTERVAL + "=" + mFlushInterval / 1000);

            if ((mType != null) && mType.equals(ILogger.PROP_SIGNED_AUDIT)) {
                v.addElement(PROP_SIGNED_AUDIT_LOG_SIGNING + "="
                            + String.valueOf(mLogSigning));

                if (mSAuditCertNickName == null) {
                    v.addElement(PROP_SIGNED_AUDIT_CERT_NICKNAME + "=");
                } else {
                    v.addElement(PROP_SIGNED_AUDIT_CERT_NICKNAME + "="
                                + mSAuditCertNickName);
                }

                v.addElement(PROP_SIGNED_AUDIT_MANDATORY_EVENTS + "=" + StringUtils.join(mandatoryEvents, ","));
                v.addElement(PROP_SIGNED_AUDIT_SELECTED_EVENTS + "=" + StringUtils.join(selectedEvents, ","));
                v.addElement(PROP_SIGNED_AUDIT_UNSELECTED_EVENTS + "=" + StringUtils.join(unselectedEvents, ","));
            }
        } catch (Exception e) {
        }
        return v;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        if (mType.equals(ILogger.PROP_SIGNED_AUDIT)) {
            String[] params = {
                    PROP_TYPE
                            + ";choice(transaction,signedAudit,system);The log event type this instance is listening to",
                    PROP_ON + ";boolean;Turn on the listener",
                    PROP_LEVEL + ";choice(" + ILogger.LL_DEBUG_STRING + "," +
                            ILogger.LL_INFO_STRING + "," +
                            ILogger.LL_WARN_STRING + "," +
                            ILogger.LL_FAILURE_STRING + "," +
                            ILogger.LL_MISCONF_STRING + "," +
                            ILogger.LL_CATASTRPHE_STRING + "," +
                            ILogger.LL_SECURITY_STRING
                            + ");Only log message with level higher than this filter will be written by this listener",
                    PROP_FILE_NAME + ";string;The name of the file the log is written to",
                    PROP_BUFFER_SIZE + ";integer;The size of the buffer to receive log messages in kilobytes(KB)",
                    PROP_FLUSH_INTERVAL
                            + ";integer;The maximum time in seconds before the buffer is flushed to the file",
                    IExtendedPluginInfo.HELP_TOKEN +
                            ";configuration-logrules-logfile",
                    IExtendedPluginInfo.HELP_TEXT +
                            ";Write the log messages to a file",
                    PROP_SIGNED_AUDIT_LOG_SIGNING +
                            ";boolean;Enable audit logs to be signed",
                    PROP_SIGNED_AUDIT_CERT_NICKNAME +
                            ";string;The nickname of the certificate to be used to sign audit logs",
                    PROP_SIGNED_AUDIT_MANDATORY_EVENTS +
                            ";string;A comma-separated list of strings used to specify mandatory signed audit log events",
                    PROP_SIGNED_AUDIT_SELECTED_EVENTS +
                            ";string;A comma-separated list of strings used to specify selected signed audit log events",
                    PROP_SIGNED_AUDIT_UNSELECTED_EVENTS +
                            ";string;A comma-separated list of strings used to specify unselected signed audit log events",
            };

            return params;
        } else {
            // mType.equals( ILogger.PROP_AUDIT )  ||
            // mType.equals( ILogger.PROP_SYSTEM )
            String[] params = {
                    PROP_TYPE
                            + ";choice(transaction,signedAudit,system);The log event type this instance is listening to",
                    PROP_ON + ";boolean;Turn on the listener",
                    PROP_LEVEL + ";choice(" + ILogger.LL_DEBUG_STRING + "," +
                            ILogger.LL_INFO_STRING + "," +
                            ILogger.LL_WARN_STRING + "," +
                            ILogger.LL_FAILURE_STRING + "," +
                            ILogger.LL_MISCONF_STRING + "," +
                            ILogger.LL_CATASTRPHE_STRING + "," +
                            ILogger.LL_SECURITY_STRING
                            + ");Only log message with level higher than this filter will be written by this listener",
                    PROP_FILE_NAME + ";string;The name of the file the log is written to",
                    PROP_BUFFER_SIZE + ";integer;The size of the buffer to receive log messages in kilobytes(KB)",
                    PROP_FLUSH_INTERVAL
                            + ";integer;The maximum time in seconds before the buffer is flushed to the file",
                    IExtendedPluginInfo.HELP_TOKEN +
                            ";configuration-logrules-logfile",
                    IExtendedPluginInfo.HELP_TEXT +
                            ";Write the log messages to a file"
            };

            return params;
        }
    }

    /**
     * Signed Audit Log
     *
     * This method is inherited by all classes that extend this "LogFile"
     * class, and is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                                null,
                                ILogger.S_SIGNED_AUDIT,
                                ILogger.LL_SECURITY,
                                msg);
    }
}
