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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.ConsoleError;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.SystemEvent;
import com.netscape.cmsutil.util.Utils;

/**
 * A rotating log file for Certificate log events. This class loosely follows
 * the Netscape Common Log API implementing rollover interval, size and file
 * naming conventions. It does not yet implement Disk Usage.
 *
 * @version $Revision$, $Date$
 */
public class RollingLogFile extends LogFile {
    public static final String PROP_MAX_FILE_SIZE = "maxFileSize";
    public static final String PROP_ROLLOVER_INTERVAL = "rolloverInterval";
    public static final String PROP_EXPIRATION_TIME = "expirationTime";

    /**
     * The default max file size in bytes
     */
    static final int MAX_FILE_SIZE = 100;

    /**
     * The default rollover interval in seconds
     */
    static final String ROLLOVER_INTERVAL = "2592000";

    /**
     * The default expiration time in seconds
     */
    static final String EXPIRATION_TIME = "2592000";

    /**
     * The maximum file size in bytes
     */
    protected int mMaxFileSize = 0;

    /**
     * The amount of time in miniseconds between log rotations
     */
    protected long mRolloverInterval = 0;

    /**
     * The thread responsible for rotating the log
     */
    private Thread mRolloverThread = null;

    /**
     * The amount of time before a backed up log is removed in milliseconds
     */
    protected long mExpirationTime = 0;

    /**
     * The thread responsible for removing expired log files
     */
    private Thread mExpirationThread = null;

    /**
     * The object used as a lock for expiration thread synchronization
     */
    private Object mExpLock = new Object();

    private final static String LOGGING_SIGNED_AUDIT_LOG_DELETE =
            "LOGGING_SIGNED_AUDIT_LOG_DELETE_3";

    /**
     * Construct a RollingLogFile
     */
    public RollingLogFile() {
    }

    /**
     * Initialize and open a RollingLogFile using the prop config store
     *
     * @param config The property config store to find values in
     */
    public void init(IConfigStore config) throws IOException,
            EBaseException {
        super.init(config);

        rl_init(config.getInteger(PROP_MAX_FILE_SIZE, MAX_FILE_SIZE),
                config.getString(PROP_ROLLOVER_INTERVAL, ROLLOVER_INTERVAL),
                config.getString(PROP_EXPIRATION_TIME, EXPIRATION_TIME));
    }

    /**
     * Convenience routine to initialized the RollingLogFile specific
     * attributes.
     */
    protected void rl_init(int maxFileSize, String rolloverInterval,
            String expirationTime) {
        mMaxFileSize = maxFileSize * 1024;
        setRolloverTime(rolloverInterval);
        setExpirationTime(expirationTime);
    }

    public void startup() throws EBaseException {
        super.startup();
    }

    /**
     * Shutdown this log file.
     */
    public synchronized void shutdown() {
        setRolloverTime("0");
        setExpirationTime("0");
        super.shutdown();
    }

    /**
     * Set the rollover interval
     *
     * @param rolloverSeconds The amount of time in seconds until the log
     *            is rotated. A value of 0 will disable log rollover.
     **/
    public synchronized void setRolloverTime(String rolloverSeconds) {
        mRolloverInterval = Long.valueOf(rolloverSeconds).longValue() * 1000;

        if ((mRolloverThread == null) && (mRolloverInterval > 0)) {
            mRolloverThread = new RolloverThread();
            mRolloverThread.setDaemon(true);
            mRolloverThread.start();
        }

        this.notify();
    }

    /**
     * Get the rollover interval
     *
     * @return The interval in seconds in which the log is rotated
     **/
    public synchronized int getRolloverTime() {
        return (int) (mRolloverInterval / 1000);
    }

    /**
     * Set the file expiration time
     *
     * @param expirationSeconds The amount of time in seconds until log files
     *            are deleted
     **/
    public void setExpirationTime(String expirationSeconds) {

        // Need to completely protect changes to mExpiration time
        // and make sure they only happen while the thread is sleeping
        synchronized (mExpLock) {
            mExpirationTime = Long.valueOf(expirationSeconds).longValue() * 1000;

            if (mExpirationThread == null) {
                if (mExpirationTime > 0) {
                    mExpirationThread = new ExpirationThread();
                    mExpirationThread.setDaemon(true);
                    mExpirationThread.start();
                }
            } else {
                mExpLock.notify();
            }
        }
    }

    /**
     * Get the expiration time
     *
     * @return The age in seconds in which log files are delete
     **/
    public int getExpirationTime() {
        return (int) (mExpirationTime / 1000);
    }

    /**
     * Rotate the log file to a backup file with timestamp
     **/
    public synchronized void rotate()
            throws IOException {

        File backupFile = new File(mFileName + "." + mLogFileDateFormat.format(mDate));

        // close, backup, and reopen the log file zeroizing its contents
        super.close();
        try {
            if (Utils.isNT()) {
                // NT is very picky on the path
                Utils.exec("copy " +
                            mFile.getCanonicalPath().replace('/', '\\') +
                            " " +
                            backupFile.getCanonicalPath().replace('/',
                                                                   '\\'));
            } else {
                // Create a copy of the original file which
                // preserves the original file permissions.
                Utils.exec("cp -p " + mFile.getCanonicalPath() + " " +
                             backupFile.getCanonicalPath());
            }

            // Zeroize the original file if and only if
            // the backup copy was successful.
            if (backupFile.exists()) {

                // Make certain that the backup file has
                // the correct permissions.
                if (!Utils.isNT()) {
                    Utils.exec("chmod 00640 " + backupFile.getCanonicalPath());
                }

                try {
                    // Open and close the original file
                    // to zeroize its contents.
                    PrintWriter pw = new PrintWriter(mFile);
                    pw.close();

                    // Make certain that the original file retains
                    // the correct permissions.
                    if (!Utils.isNT()) {
                        Utils.exec("chmod 00640 " + mFile.getCanonicalPath());
                    }
                } catch (FileNotFoundException e) {
                    CMS.debug("Unable to zeroize "
                             + mFile.toString());
                }
            } else {
                CMS.debug("Unable to backup "
                         + mFile.toString() + " to "
                         + backupFile.toString());
            }
        } catch (Exception e) {
            CMS.debug("Unable to backup "
                     + mFile.toString() + " to "
                     + backupFile.toString());
        }
        super.open(); // will reset mBytesWritten
    }

    /**
     * Remove any log files which have not been modified in the specified
     * time
     * <P>
     *
     * NOTE: automatic removal of log files is currently NOT supported!
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_LOG_DELETE used AFTER audit log expires (authorization should not allow,
     * but in case authorization gets compromised make sure it is written AFTER the log expiration happens)
     * </ul>
     *
     * @param expirationSeconds The number of seconds since the expired files
     *            have been modified.
     * @return the time in milliseconds when the next file expires
     **/
    public long expire(long expirationSeconds) throws ELogException {
        String auditMessage = null;

        if (expirationSeconds <= 0)
            throw new ELogException(CMS.getUserMessage("CMS_LOG_EXPIRATION_TIME_ZERO"));

        long expirationTime = expirationSeconds * 1000;
        long currentTime = System.currentTimeMillis();
        long oldestFile = currentTime;

        String dirName = mFile.getParent();

        if (dirName == null)
            dirName = ".";
        File dir = new File(dirName);

        // Get just the base name, minus the .date extension
        //int len = mFile.getName().length() - LogFile.DATE_PATTERN.length() - 1;
        //String baseName = mFile.getName().substring(0, len);
        String fileName = mFile.getName();
        String baseName = null, pathName = null;
        int index = fileName.lastIndexOf("/");

        if (index != -1) { // "/"  exist in fileName
            pathName = fileName.substring(0, index);
            baseName = fileName.substring(index + 1);
            dirName = dirName.concat("/" + pathName);
        } else { // "/" NOT exist in fileName
            baseName = fileName;
        }

        fileFilter ff = new fileFilter(baseName + ".");
        String[] filelist = dir.list(ff);

        if (filelist == null) { // Crap!  Something is wrong.
            throw new ELogException(CMS.getUserMessage("CMS_LOG_DIRECTORY_LIST_FAILED",
                    dirName, ff.toString()));
        }

        // Walk through the list of files which match this log file name
        // and delete the old ones.
        for (int i = 0; i < filelist.length; i++) {
            if (pathName != null) {
                filelist[i] = pathName + "/" + filelist[i];
            } else {
                filelist[i] = dirName + "/" + filelist[i];
            }

            String fullname = dirName + File.separatorChar + filelist[i];
            File file = new File(fullname);
            long fileTime = file.lastModified();

            // Java documentation on File says lastModified() should not
            // be interpeted.  The doc is wrong.  See JavaSoft bug #4094538
            if ((currentTime - fileTime) > expirationTime) {
                file.delete();

                if (file.exists()) {
                    // log failure in deleting an expired signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_LOG_DELETE,
                                ILogger.SYSTEM_UID,
                                ILogger.FAILURE,
                                fullname);
                } else {
                    // log success in deleting an expired signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_LOG_DELETE,
                                ILogger.SYSTEM_UID,
                                ILogger.SUCCESS,
                                fullname);
                }

                audit(auditMessage);
            } else if (fileTime < oldestFile) {
                oldestFile = fileTime;
            }
        }
        return oldestFile + expirationTime;
    }

    //
    // Rollover and Expiration threads
    //
    // At first glance you may think it's a waste of thread resources to have
    // two threads for every log file, but the truth is that these threads are
    // sleeping 99% of the time.  NxN thread implementations (Solaris, NT,
    // IRIX 6.4, Unixware, etc...) will handle these in user space.
    //
    // You may be able to join these into one thread, and deal with
    // multiple wakeup times, but the code would sure look ugly, and the race
    // conditions are numerous as is. Furthermore, this is what user space
    // threads will do for you anyways.
    //

    /**
     * Log rotation thread. Sleep for the rollover interval and rotate the
     * log. Changing rollover interval to 0 will cause this thread to exit.
     */
    final class RolloverThread extends Thread {

        /**
         * Rollover thread constructor including thread name
         */
        public RolloverThread() {
            super();
            super.setName(mFileName + ".rollover-" + (Thread.activeCount() + 1));
        }

        public void run() {
            while (mRolloverInterval > 0) {
                // Sleep for the interval and then rotate the log
                synchronized (RollingLogFile.this) {
                    try {
                        RollingLogFile.this.wait(mRolloverInterval);
                    } catch (InterruptedException e) {
                        // This shouldn't happen very often
                        CMS.getLogger().getLogQueue().log(new
                                SystemEvent(CMS.getUserMessage("CMS_LOG_THREAD_INTERRUPT", "rollover")));
                    }
                }

                if (mRolloverInterval == 0) {
                    break;
                }

                if (mBytesWritten > 0) {
                    try {
                        rotate();
                    } catch (IOException e) {
                        ConsoleError.send(new
                                SystemEvent(CMS.getUserMessage("CMS_LOG_ROTATE_LOG_FAILED", mFile.getName(),
                                        e.toString())));
                        break;
                    }
                }
                // else
                //   Don't rotate empty logs
                //   flag in log summary file?
            }
            mRolloverThread = null;
        }
    }

    /**
     * Log expiration thread. Sleep for the expiration interval and
     * delete any files which are too old.
     * Changing expiration interval to 0 will cause this thread to exit.
     */
    final class ExpirationThread extends Thread {

        /**
         * ExpirationThread thread constructor including thread name
         */
        public ExpirationThread() {
            super();
            super.setName(mFileName + ".expiration-" + (Thread.activeCount() + 1));
        }

        public void run() {
            synchronized (mExpLock) {
                while (mExpirationTime > 0) {
                    long wakeupTime = 0;
                    long sleepTime = 0;

                    // First, remove any old log files and figure out when the
                    // next one expires
                    try {
                        wakeupTime = expire(mExpirationTime / 1000);
                    } catch (SecurityException e) {
                        ConsoleError.send(new
                                SystemEvent(CMS.getUserMessage("CMS_LOG_EXPIRE_LOG_FAILED", e.toString())));
                        break;
                    } catch (ELogException e) {
                        ConsoleError.send(new
                                SystemEvent(CMS.getUserMessage("CMS_LOG_EXPIRE_LOG_FAILED", e.toString())));
                        break;
                    }

                    sleepTime = wakeupTime - System.currentTimeMillis();
                    //System.out.println("wakeup " + wakeupTime);
                    //System.out.println("current "+System.currentTimeMillis());
                    //System.out.println("sleep " + sleepTime);
                    // Sleep for the interval and then check the directory
                    // Note: mExpirationTime can only change while we're
                    // sleeping
                    if (sleepTime > 0) {
                        try {
                            mExpLock.wait(sleepTime);
                        } catch (InterruptedException e) {
                            // This shouldn't happen very often
                            ConsoleError.send(new
                                    SystemEvent(CMS.getUserMessage("CMS_LOG_THREAD_INTERRUPT", "expiration")));
                        }
                    }
                }
            }
            mExpirationThread = null;
        }
    }

    /**
     * Write an event to the log file
     *
     * @param ev The event to be logged.
     **/
    public synchronized void log(ILogEvent ev) throws ELogException {
        //xxx, Shall we log first without checking if it exceed the maximum?
        super.log(ev); // Will increment mBytesWritten

        if ((0 != mMaxFileSize) && (mBytesWritten > mMaxFileSize)) {
            flush();
            try {
                rotate();
            } catch (IOException e) {
                throw new ELogException(CMS.getUserMessage("CMS_LOG_ROTATE_LOG_FAILED", mFile.getName(), e.toString()));
            }
        }
    }

    /**
     * Retrieve log file list.
     */
    public synchronized NameValuePairs retrieveLogList(Hashtable<String, String> req
            ) throws ServletException,
                    IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        String[] files = null;

        files = fileList();
        for (int i = 0; i < files.length; i++) {
            params.put(files[i], "");
        }
        return params;
    }

    /**
     * Get the log file list in the log directory
     *
     * @return an array of filenames with related path to cert server root
     */
    protected String[] fileList() {
        String pathName = null, baseName = null;

        String dirName = mFile.getParent();
        String fileName = mFile.getName();
        int index = fileName.lastIndexOf("/");

        if (index != -1) { // "/"  exist in fileName
            pathName = fileName.substring(0, index);
            baseName = fileName.substring(index + 1);
            if (dirName == null) {
                dirName = pathName;
            } else {
                dirName = dirName.concat("/" + pathName);
            }
        } else { // "/" NOT exist in fileName
            baseName = fileName;
        }

        File dir = new File(dirName);

        fileFilter ff = new fileFilter(baseName + ".");
        //There are some difference here. both should work
        //error,logs,logs/error jdk115
        //logs/system,., logs/system jdk116
        //System.out.println(mFile.getName()+","+dirName+","+mFile.getPath()); //log/system,.

        String[] filelist = dir.list(ff);

        for (int i = 0; i < filelist.length; i++) {
            if (pathName != null) {
                filelist[i] = pathName + "/" + filelist[i];
            } else {
                filelist[i] = dirName + "/" + filelist[i];
            }
        }
        return filelist;
    }

    public String getImplName() {
        return "RollingLogFile";
    }

    public String getDescription() {
        return "RollingLogFile";
    }

    public Vector<String> getDefaultParams() {
        Vector<String> v = super.getDefaultParams();

        v.addElement(PROP_MAX_FILE_SIZE + "=");
        v.addElement(PROP_ROLLOVER_INTERVAL + "=");
        //v.addElement(PROP_EXPIRATION_TIME + "=");
        return v;
    }

    public Vector<String> getInstanceParams() {
        Vector<String> v = super.getInstanceParams();

        try {
            v.addElement(PROP_MAX_FILE_SIZE + "=" + mMaxFileSize / 1024);
            if (mRolloverInterval / 1000 <= 60 * 60)
                v.addElement(PROP_ROLLOVER_INTERVAL + "=" + "Hourly");
            else if (mRolloverInterval / 1000 <= 60 * 60 * 24)
                v.addElement(PROP_ROLLOVER_INTERVAL + "=" + "Daily");
            else if (mRolloverInterval / 1000 <= 60 * 60 * 24 * 7)
                v.addElement(PROP_ROLLOVER_INTERVAL + "=" + "Weekly");
            else if (mRolloverInterval / 1000 <= 60 * 60 * 24 * 30)
                v.addElement(PROP_ROLLOVER_INTERVAL + "=" + "Monthly");
            else if (mRolloverInterval / 1000 <= 60 * 60 * 24 * 366)
                v.addElement(PROP_ROLLOVER_INTERVAL + "=" + "Yearly");

            //v.addElement(PROP_EXPIRATION_TIME + "=" + mExpirationTime / 1000);
        } catch (Exception e) {
        }
        return v;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        String[] p = super.getExtendedPluginInfo(locale);
        Vector<String> info = new Vector<String>();

        for (int i = 0; i < p.length; i++) {
            if (!p[i].startsWith(IExtendedPluginInfo.HELP_TOKEN) && !p[i].startsWith(IExtendedPluginInfo.HELP_TEXT))
                info.addElement(p[i]);
        }
        info.addElement(PROP_MAX_FILE_SIZE
                + ";integer;If the current log file size if bigger than this parameter in kilobytes(KB), the file will be rotated.");
        info.addElement(PROP_ROLLOVER_INTERVAL
                + ";choice(Hourly,Daily,Weekly,Monthly,Yearly);The frequency of the log being rotated.");
        info.addElement(PROP_EXPIRATION_TIME
                + ";integer;The amount of time before a backed up log is removed in seconds");
        info.addElement(IExtendedPluginInfo.HELP_TOKEN +
                //";configuration-logrules-rollinglogfile");
                ";configuration-adminbasics");
        info.addElement(IExtendedPluginInfo.HELP_TEXT +
                ";Write the log messages to a file which will be rotated automatically.");
        String[] params = new String[info.size()];

        info.copyInto(params);
        return params;

    }
}

/**
 * A file filter to select the file with a given prefix
 */
class fileFilter implements FilenameFilter {
    String patternToMatch = null;

    public fileFilter(String pattern) {
        patternToMatch = pattern;
    }

    public boolean accept(File dir, String name) {
        if (name.startsWith(patternToMatch))
            return true;
        else
            return false;
    }
}
