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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import javax.servlet.ServletException;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.util.Base64OutputStream;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ConsoleError;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogSource;
import com.netscape.certsrv.logging.SignedAuditEvent;
import com.netscape.certsrv.logging.SystemEvent;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

import netscape.ldap.client.JDAPAVA;
import netscape.ldap.client.JDAPFilter;
import netscape.ldap.client.JDAPFilterAnd;
import netscape.ldap.client.JDAPFilterEqualityMatch;
import netscape.ldap.client.JDAPFilterNot;
import netscape.ldap.client.JDAPFilterOr;
import netscape.ldap.client.JDAPFilterPresent;
import netscape.ldap.client.JDAPFilterSubString;

/**
 * A log event listener which write logs to log files
 *
 * @version $Revision$, $Date$
 **/
public class LogFile implements ILogEventListener, IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LogFile.class);
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    public static final String PROP_TYPE = "type";
    public static final String PROP_REGISTER = "register";
    public static final String PROP_ON = "enable";
    public static final String PROP_TRACE = "trace";
    public static final String PROP_SIGNED_AUDIT_LOG_SIGNING = "logSigning";
    public static final String PROP_SIGNED_AUDIT_CERT_NICKNAME =
                              "signedAuditCertNickname";
    public static final String PROP_SIGNED_AUDIT_SELECTED_EVENTS = "events";
    public static final String PROP_SIGNED_AUDIT_MANDATORY_EVENTS = "mandatory.events";
    public static final String PROP_SIGNED_AUDIT_FILTERS = "filters";

    public static final String PROP_LEVEL = "level";
    static final String PROP_FILE_NAME = "fileName";
    static final String PROP_LAST_HASH_FILE_NAME = "lastHashFileName";
    static final String PROP_BUFFER_SIZE = "bufferSize";
    static final String PROP_FLUSH_INTERVAL = "flushInterval";

    private final static String LOG_SIGNED_AUDIT_EXCEPTION =
                               "LOG_SIGNED_AUDIT_EXCEPTION_1";

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
     * The event filters
     */
    protected Map<String, JDAPFilter> filters = new HashMap<String, JDAPFilter>();

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
                logger.debug("LogFile: audit log signing enabled. signedAuditCertNickname: " + mSAuditCertNickName);
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

        logger.debug("Event filters:");
        IConfigStore filterStore = config.getSubStore(PROP_SIGNED_AUDIT_FILTERS);
        for (Enumeration<String> e = filterStore.getPropertyNames(); e.hasMoreElements(); ) {
            String eventType = e.nextElement();

            // get event filter
            String strFilter = filterStore.get(eventType);
            logger.debug(" - " + eventType + ": " + strFilter);

            // parse filter
            JDAPFilter filter = JDAPFilter.getFilter(strFilter);
            filters.put(eventType, filter);
        }

        try {
            init(config);
        } catch (IOException e) {
            throw new ELogException("Unable to initialize LogFile: " + e.getMessage(), e);
        }

        // set up signing here to ensure audit logs generated during
        // subsequent component initialization are signed properly
        if (mOn && mLogSigning) {

            try {
                logger.debug("LogFile: setting up log signing");
                setupSigning();

                signedAuditLogger.log(CMS.getLogMessage(
                        AuditEvent.AUDIT_LOG_STARTUP,
                        ILogger.SYSTEM_UID,
                        ILogger.SUCCESS));

            } catch (EBaseException e) {

                signedAuditLogger.log(CMS.getLogMessage(
                        AuditEvent.AUDIT_LOG_STARTUP,
                        ILogger.SYSTEM_UID,
                        ILogger.FAILURE));

                throw e;
            }
        }
    }

    /**
     * add the event to the selected events list
     *
     * @param event to be selected
     */
    public void selectEvent(String event) {
        selectedEvents.add(event);
    }

    /**
     * remove the event from the selected events list
     *
     * @param event to be de-selected
     */
    public void deselectEvent(String event) {
        selectedEvents.remove(event);
    }

    /**
     * replace the selected events list
     *
     * @param events comma-separated event list
     */
    public void replaceEvents(String events) {
        // unselect all events
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

            logger.error("LogFile: Disabling subsystem due to signed logging failure");

            CMSEngine engine = CMS.getCMSEngine();
            engine.disableSubsystem();
        }
    }

    /**
     * Initialize and open the log using the parameters from a config store
     *
     * @param config The property config store to find values in
     */
    public void init(IConfigStore config) throws IOException,
            EBaseException {

        CMSEngine engine = CMS.getCMSEngine();
        String fileName = null;
        String defaultFileName = null;
        String signedAuditDefaultFileName = "";

        mConfig = config;

        mTrace = config.getBoolean(PROP_TRACE, false);
        mType = config.getString(PROP_TYPE, "system");
        mRegister = config.getBoolean(PROP_REGISTER, true);

        if (mOn) {
            if (mRegister) {
                Logger.getLogger().getLogQueue().addLogEventListener(this);
            }
        } else {
            // shutdown the listener, remove the listener
            if (mRegister) {
                Logger.getLogger().getLogQueue().removeLogEventListener(this);
                shutdown();
            }
        }

        mLevel = config.getInteger(PROP_LEVEL, 3);

        try {
            // retrieve the subsystem
            String subsystem = "";

            ISubsystem caSubsystem = engine.getSubsystem(ICertificateAuthority.ID);
            if (caSubsystem != null) {
                subsystem = ICertificateAuthority.ID;
            }

            ISubsystem raSubsystem = engine.getSubsystem(IRegistrationAuthority.ID);
            if (raSubsystem != null) {
                subsystem = IRegistrationAuthority.ID;
            }

            ISubsystem kraSubsystem = engine.getSubsystem(IKeyRecoveryAuthority.ID);
            if (kraSubsystem != null) {
                subsystem = IKeyRecoveryAuthority.ID;
            }

            ISubsystem ocspSubsystem = engine.getSubsystem(IOCSPAuthority.ID);
            if (ocspSubsystem != null) {
                subsystem = IOCSPAuthority.ID;
            }

            // retrieve the instance name
            String instIDPath = engine.getInstanceDir();
            int index = instIDPath.lastIndexOf("/");
            String instID = instIDPath.substring(index + 1);

            // build the default signedAudit file name
            signedAuditDefaultFileName = subsystem + "_"
                                       + instID + "_" + "audit";

        } catch (Exception e2) {
            String message = CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_FILE_NAME);
            logger.error("LogFile: " + message + ": " + e2.getMessage(), e2);
            throw new ELogException(message, e2);
        }

        // the default value is determined by the eventType.
        if (mType.equals(ILogger.PROP_SIGNED_AUDIT)) {
            defaultFileName = "logs/signedAudit/" + signedAuditDefaultFileName;
        } else if (mType.equals(ILogger.PROP_SYSTEM)) {
            defaultFileName = "logs/system";
        } else if (mType.equals(ILogger.PROP_AUDIT)) {
            defaultFileName = "logs/transactions";
        } else {
            String message = CMS.getUserMessage("CMS_LOG_INVALID_LOG_TYPE",
                    config.getName(), mType);
            logger.error("LogFile: " + message);
            throw new ELogException(message);
        }

        try {
            fileName = config.getString(PROP_FILE_NAME, defaultFileName);
        } catch (EBaseException e) {
            String message = CMS.getUserMessage("CMS_BASE_GET_PROPERTY_FAILED",
                    config.getName() + "." + PROP_FILE_NAME);
            logger.error("LogFile: " + message + ": " + e.getMessage(), e);
            throw new ELogException(message, e);
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

        logger.debug("LogFile: Creating " + getClass().getSimpleName() + "(" + fileName + ")");

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
                logger.debug("LogFile: provider " + i + "= " + providers[i].getName());
            }

            CryptoManager cm = CryptoManager.getInstance();

            // find CertServer's private key
            X509Certificate cert = cm.findCertByNickname(mSAuditCertNickName);
            if (cert != null) {
                logger.debug("LogFile: setupSignig(): found cert:" + mSAuditCertNickName);
            } else {
                logger.warn("LogFile: setupSignig(): cert not found:" + mSAuditCertNickName);
            }
            mSigningKey = cm.findPrivKeyByCert(cert);

            String sigAlgorithm;
            if (mSigningKey.getAlgorithm().equalsIgnoreCase("RSA")) {
                sigAlgorithm = "SHA-256/RSA";
            } else if (mSigningKey.getAlgorithm().equalsIgnoreCase("EC")) {
                sigAlgorithm = "SHA-256/EC";
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

        } catch (NotInitializedException nie) {
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
     * <li>signed.audit AUDIT_LOG_SIGNING used when a signature on the audit log is generated (same as
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
                AuditEvent.AUDIT_LOG_SIGNING,
                ILogger.SYSTEM_UID,
                ILogger.SUCCESS,
                base64Encode(sigBytes));

        ILogEvent ev = signedAuditLogger.create(
                ILogger.LL_SECURITY,
                auditMessage,
                o,
                ILogger.L_SINGLELINE);

        doLog(ev, true);
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
                    String message = "Unable to change file permissions on "
                             + mFile + ": " + e.getMessage();
                    logger.warn(message, e);
                }
            }
            mLogWriter = new BufferedWriter(
                        new FileWriter(out.getFD()), mBufferSize);

            // The first time we open, mSignature will not have been
            // initialized yet. That's ok, we will push our first signature
            // in setupSigning().
            if (mLogSigning && (mSignature != null)) {
                pushSignature();
            }

        } catch (ELogException e) {
            String message = CMS.getUserMessage("CMS_LOG_ILLEGALARGUMENT", mFileName);
            logger.warn("LogFile: " + message + ": " + e.getMessage(), e);
            ConsoleError.send(new SystemEvent(message));

        } catch (IllegalArgumentException iae) {
            String message = CMS.getUserMessage("CMS_LOG_ILLEGALARGUMENT", mFileName);
            logger.warn("LogFile: " + message + ": " + iae.getMessage(), iae);
            ConsoleError.send(new SystemEvent(message));

        } catch (GeneralSecurityException gse) {
            // error with signed audit log, shutdown CMS
            String message = CMS.getUserMessage("CMS_LOG_OPEN_FAILED", mFileName, gse.getMessage());
            logger.error("LogFile: " + message, gse);
            ConsoleError.send(new SystemEvent(message));
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
                pushSignature();
            }

            if (mLogWriter != null) {
                mLogWriter.flush();
            }

        } catch (Exception e) {
            String message = CMS.getUserMessage("CMS_LOG_FLUSH_LOG_FAILED", mFileName, e.getMessage());
            logger.error("LogFile: " + message, e);
            ConsoleError.send(new SystemEvent(message));
            if (mLogSigning) {
                e.printStackTrace();
                shutdownCMS();
            }
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
     * <li>signed.audit AUDIT_LOG_SHUTDOWN used at audit function shutdown
     * </ul>
     */
    public synchronized void shutdown() {

        logger.info("Destroying LogFile(" + mFileName + ")");

        String auditMessage = null;

        setFlushInterval(0);

        // log signed audit shutdown success
        auditMessage = CMS.getLogMessage(
                           AuditEvent.AUDIT_LOG_SHUTDOWN,
                           ILogger.SYSTEM_UID,
                           ILogger.SUCCESS);

        signedAuditLogger.log(auditMessage);

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

        if (mFlushThread == null && mFlushInterval > 0) {
            mFlushThread = new FlushThread();
            mFlushThread.setDaemon(true);
            mFlushThread.start();

        } else if (mFlushThread != null && mFlushInterval == 0) {
            mFlushThread.interrupt();
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
                        // shutdown
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
     * Synchronized method to write an event to the log file.
     *
     * @param event The log event
     */
    protected synchronized void doLog(ILogEvent event) throws ELogException {
        doLog(event, false);
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
    private synchronized void doLog(ILogEvent event, boolean noFlush)
            throws ELogException {

        String entry = logEvt2String(event);

        if (mLogWriter == null) {
            String[] params = { mFileName, entry };

            String message = CMS.getUserMessage("CMS_LOG_LOGFILE_CLOSED", params);
            logger.error("LogFile: " + message);
            ConsoleError.send(new SystemEvent(message));
            if (mLogSigning) {
                // Failed to write to audit log, shut down CMS
                shutdownCMS();
            }
            throw new ELogException(message);

        } else {
            try {
                mLogWriter.write(entry, 0/*offset*/, entry.length());

                if (mLogSigning == true) {
                    if (mSignature != null) {
                        // include newline for calculating MAC
                        mSignature.update(entry.getBytes("UTF-8"));
                    } else {
                        logger.warn("LogFile: missing audit log signature");
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
                        logger.warn("LogFile: missing audit log signature");
                    }
                }

            } catch (IOException e) {
                String message = CMS.getUserMessage("CMS_LOG_WRITE_FAILED", mFileName, entry, e.getMessage());
                logger.error("LogFile: " + message);
                ConsoleError.send(new SystemEvent(message));
                if (mLogSigning) {
                    // Failed to write to audit log, shut down CMS
                    e.printStackTrace();
                    shutdownCMS();
                }

            } catch (IllegalStateException e) {
                String message = CMS.getLogMessage(LOG_SIGNED_AUDIT_EXCEPTION, e.getMessage());
                logger.error("LogFile: " + message, e);
                ConsoleError.send(new SignedAuditEvent(message));

            } catch (GeneralSecurityException gse) {
                // DJN: handle error
                String message = CMS.getLogMessage(LOG_SIGNED_AUDIT_EXCEPTION, gse.getMessage());
                logger.error("LogFile: " + message, gse);
                ConsoleError.send(new SignedAuditEvent(message));

            } catch (Exception ee) { // Make darn sure we got everything
                String message = CMS.getLogMessage(LOG_SIGNED_AUDIT_EXCEPTION, ee.getMessage());
                logger.error("LogFile: " + message, ee);
                ConsoleError.send(new SignedAuditEvent(message));
                if (mLogSigning) {
                    // Failed to write to audit log, shut down CMS
                    ee.printStackTrace();
                    shutdownCMS();
                }

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

        if (!mOn || mLevel > ev.getLevel()) {
            return;
        }

        if (ev instanceof AuditEvent && !mType.equals("transaction")) {
            return;

        } else if (ev instanceof SystemEvent && !mType.equals("system")) {
            return;

        } else if (ev instanceof SignedAuditEvent && !mType.equals("signedAudit")) {
            return;
        }

        // If no type specified in property file, then treated as selected
        String type = ev.getEventType();
        if (type == null) {
            doLog(ev);
            return;
        }

        // If no selection specified in configuration, then all are selected
        if (selectedEvents.isEmpty()) {
            filter((SignedAuditEvent)ev);
            return;
        }

        // Is the event type mandatory or selected?
        if (mandatoryEvents.contains(type) || selectedEvents.contains(type)) {
            filter((SignedAuditEvent)ev);
            return;
        }

        logger.debug("LogFile: event type not selected: " + type);
    }

    public void filter(SignedAuditEvent ev) throws ELogException {
        String type = ev.getEventType();
        JDAPFilter filter = filters.get(type);

        if (filter == null) {
            // filter not defined for this event type
            doLog(ev);
            return;
        }

        try {
            boolean result = eval(ev, filter);
            if (!result) {
                // event does not match filter, discard
                return;
            }

        } catch (Exception e) {
            throw new ELogException(e.getMessage(), e);
        }

        // log event
        doLog(ev);
    }

    public boolean eval(SignedAuditEvent event, JDAPFilter filter) {

        if (filter instanceof JDAPFilterPresent) {
            return eval(event, (JDAPFilterPresent)filter);

        } else if (filter instanceof JDAPFilterEqualityMatch) {
            return eval(event, (JDAPFilterEqualityMatch)filter);

        } else if (filter instanceof JDAPFilterSubString) {
            return eval(event, (JDAPFilterSubString)filter);

        } else if (filter instanceof JDAPFilterAnd) {
            return eval(event, (JDAPFilterAnd)filter);

        } else if (filter instanceof JDAPFilterOr) {
            return eval(event, (JDAPFilterOr)filter);

        } else if (filter instanceof JDAPFilterNot) {
            return eval(event, (JDAPFilterNot)filter);

        } else {
            return false;
        }
    }

    public boolean eval(SignedAuditEvent event, JDAPFilterPresent filter) {

        // filter: (<name>=*)

        String name = filter.getType();
        Object attr = event.getAttribute(name);

        return attr != null;
    }

    public boolean eval(SignedAuditEvent event, JDAPFilterEqualityMatch filter) {

        // filter: (<name>=<value>)

        JDAPAVA ava = filter.getAVA();
        String name = ava.getType();
        String value = ava.getValue();

        Object attr = event.getAttribute(name);

        if (attr == null) return false;
        if (!(attr instanceof String)) return false;

        String stringAttr = (String)attr;

        return value.equalsIgnoreCase(stringAttr);
    }

    public boolean eval(SignedAuditEvent event, JDAPFilterSubString filter) {

        // filter: (<name>=<initial>*<any>*...*<any>*<final>)

        String name = filter.getType();
        Object attr = event.getAttribute(name);

        if (attr == null) return false;
        if (!(attr instanceof String)) return false;

        String stringAttr = ((String)attr).toLowerCase();

        // check initial substring
        String initialSubstring = filter.getInitialSubstring();
        if (initialSubstring != null) {
            if (!stringAttr.startsWith(initialSubstring.toLowerCase())) return false;
            stringAttr = stringAttr.substring(initialSubstring.length());
        }

        // check any substrings
        for (String anySubstring : filter.getAnySubstrings()) {
            int p = stringAttr.indexOf(anySubstring.toLowerCase());
            if (p < 0) return false;
            stringAttr = stringAttr.substring(p + anySubstring.length());
        }

        // check final substring
        String finalSubstring = filter.getFinalSubstring();
        if (finalSubstring != null) {
            if (!stringAttr.endsWith(finalSubstring.toLowerCase())) return false;
        }

        return true;
    }

    public boolean eval(SignedAuditEvent event, JDAPFilterAnd filter) {

        // filter: (&(filter1)(filter2)...(filterN))

        for (JDAPFilter f : filter.getFilters()) {
            if (!eval(event, f)) return false;
        }

        return true;
    }

    public boolean eval(SignedAuditEvent event, JDAPFilterOr filter) {

        // filter: (|(filter1)(filter2)...(filterN))

        for (JDAPFilter f : filter.getFilters()) {
            if (eval(event, f)) return true;
        }

        return false;
    }

    public boolean eval(SignedAuditEvent event, JDAPFilterNot filter) {

        // filter: (!(filter))

        JDAPFilter f = filter.getFilter();

        return !eval(event, f);
    }

    public String logEvt2String(ILogEvent ev) {
        String entry = null;

        // Hmm.. multiple threads could hit this and reset the time.
        // Do we care?
        mDate.setTime(ev.getTimeStamp());

        CMSEngine engine = CMS.getCMSEngine();

        // XXX
        // This should follow the Common Log Format which still needs
        // some work.
        if (ev.getMultiline() == ILogger.L_MULTILINE) {
            entry = engine.getPID() + "." + Thread.currentThread().getName() + " - ["
                    + mLogDateFormat.format(mDate) + "] [" +
                    ev.getSource().value() + "] [" + Integer.toString(ev.getLevel())
                    + "] " + prepareMultiline(ev.toString());
        } else {
            entry = engine.getPID() + "." + Thread.currentThread().getName() + " - ["
                    + mLogDateFormat.format(mDate) + "] [" +
                    ev.getSource().value() + "] [" + Integer.toString(ev.getLevel())
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
    public Vector<LogEntry> readEntry(int maxLine, int lowLevel, LogSource source, String fName) {
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
                                            ((Integer.parseInt(preLogEntry.getSource()) == source.value()) ||
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
                    logger.warn(CMS.getLogMessage("LOGGING_READ_ERROR", fileName, Integer.toString(lineNo)), e);
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
                                ((Integer.parseInt(preLogEntry.getSource()) == source.value()) ||
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
                            ((Integer.parseInt(preLogEntry.getSource()) == source.value())
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
                logger.warn("logging:" + fileName + " failed to close for reading", e);
            }

        } catch (FileNotFoundException e) {
            logger.warn(CMS.getLogMessage("LOGGING_FILE_NOT_FOUND", fileName), e);
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
        int maxLine = -1, level = -1;
        LogSource source = null;
        Vector<LogEntry> entries = null;

        if ((tmp = req.get(Constants.PR_LOG_ENTRY)) != null) {
            maxLine = Integer.parseInt(tmp);
        }
        if ((tmp = req.get(Constants.PR_LOG_LEVEL)) != null) {
            level = Integer.parseInt(tmp);
        }
        if ((tmp = req.get(Constants.PR_LOG_SOURCE)) != null) {
            source = LogSource.valueOf(Integer.parseInt(tmp));
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
            logger.warn("System log parse error: " + e.getMessage(), e);
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
                            ";string;A comma-separated list of strings used to specify selected signed audit log events"
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
}
