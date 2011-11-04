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
package com.netscape.cmscore.util;


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.base.SubsystemRegistry;
import com.netscape.osutil.LibC;
import com.netscape.osutil.OSUtil;
import com.netscape.osutil.ResourceLimit;
import com.netscape.osutil.Signal;
import com.netscape.osutil.SignalListener;
import com.netscape.osutil.UserID;


/**
 * This object contains the OS independent interfaces.  It's currently
 * used for Unix signal and user handling, but could eventually be extended
 * for NT interfaces.
 * <P>
 *
 * @author mikep
 * @version $Revision$, $Date$
 */
public final class OsSubsystem implements ISubsystem {

    public static final String ID = "os";
    protected IConfigStore mConfig;
    protected String mInstanceDir;
    protected ISubsystem mOwner;
    protected ILogger mLogger = null;
    protected static SignalThread mSignalThread = null;

    private static final String PROP_OS = "os";
    private static final String PROP_USERID = "userid";

    // singleton enforcement

    private static OsSubsystem mInstance = new OsSubsystem();

    public static OsSubsystem getInstance() {
        return mInstance;
    }

    // end singleton enforcement.

    /**
     * Constructor for an OS subsystem
     */
    private OsSubsystem() {
    }

    /**
     * Retrieves subsystem name.
     */
    public String getId() {
        return ID;
    }

    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     * @exception EBaseException failed to initialize
     */
    public void init(ISubsystem owner, IConfigStore config)
        throws EBaseException {

        mOwner = owner;
        mConfig = config;
        mLogger = CMS.getLogger();

        mInstanceDir = CMS.getConfigStore().getString("instanceRoot");

        // We currently only deal with Unix and NT
        if (isUnix()) {
            //initUnix();
        } else {
            initNT();
        }
        try {
            //System.out.println(" The dir I'm seeing is " + mInstanceDir);
            String pidName = mInstanceDir + File.separator + "config" + File.separator + "cert-pid";
            BufferedWriter pidOut = new BufferedWriter(new FileWriter(pidName));
            int pid = OsSubsystem.getpid();

            pidOut.write(Integer.toString(pid));
            pidOut.close();
            OSUtil.getFileWriteLock(pidName);
        } catch (Exception e) {
            //XX to stderr XXXXXX
            //e.printStackTrace();
        }
    }

    /**
     * Starts up OS
     */
    public void startup() throws EBaseException {
        if (isUnix()) {
            String pf = mConfig.getString("pidFile", null);

            if (pf == null) {
                return; // development environment does not rely on this
            }
            // dont ever call detach in Java environment,
            // it does a fork()
            // LibC.detach();

            // need to do pid here, pid will be changed after detach
            int pid = LibC.getpid();
            String pidStr = Integer.toString(pid);

            try {
                FileOutputStream fos = new FileOutputStream(pf);

                fos.write(pidStr.getBytes());
                fos.close();
            } catch (IOException e) {

                /*LogDoc
                 *
                 * @phase start OS subsystem
                 * @message OS: <exception thrown>
                 */
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, "OS: " + e.toString());
            }
        }
    }

    /**
     * Returns the process ID of the Certificate Server process. Works
     * on Unix and NT.
     */
    public static int getpid() {
        if (isUnix()) {
            return LibC.getpid();
        } else {
            return OSUtil.getNTpid();
        }
    }

    /**
     * Hooks up unix signals.
     */
    private void initUnix() throws EBaseException {
        // Set up signal handling.  We pretty much exit on anything
        // Signal.watch(Signal.SIGHUP); 
        // Signal.watch(Signal.SIGTERM);
        // Signal.watch(Signal.SIGINT);
        // mSignalThread = new SignalThread();
        // mSignalThread.setDaemon(true);
        // mSignalThread.start();

        Signal.addSignalListener(Signal.SIGHUP, new SIGHUPListener(this)); 
        Signal.addSignalListener(Signal.SIGTERM, new SIGTERMListener(this)); 
        Signal.addSignalListener(Signal.SIGINT, new SIGINTListener(this)); 

        /* Increase the maximum number of file descriptors */
        int i = mConfig.getInteger("maxFiles", 
                ResourceLimit.getHardLimit(ResourceLimit.RLIMIT_NOFILE));

        ResourceLimit.setLimits(ResourceLimit.RLIMIT_NOFILE,
            i, ResourceLimit.getHardLimit(ResourceLimit.RLIMIT_NOFILE));

        // write current pid to specified file
        String pf = mConfig.getString("pidFile", null);

        if (pf == null) {
            return; // development environment does not rely on this
        }
        File pidFile = new File(pf);

        if (pidFile.exists()) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_PID_EXIST"));
        }
    }

    /**
     * Used to change the process user id usually called after the appropriate 
     * network ports have been opened.
     */
    public void setUserId() throws EBaseException {
        if (!isUnix())
            return;

        String userid;

        userid = mConfig.getString(PROP_USERID, null);
        String id = String.valueOf(UserID.get());

        // Change the userid to the prefered Unix user
        if (userid == null) {

            /*LogDoc
             *
             * @phase set user id
             * @arg0 default user id
             */
            mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                ILogger.LL_FAILURE, 
                "OS: No user id in config file.  Running as {0}", id);
        } else {
            Object[] params = {userid, id};

            try {
                UserID.set(userid);
            } catch (IllegalArgumentException e) {

                /*LogDoc
                 *
                 * @phase set user id
                 * @arg0 supplied user id in config
                 * @arg1 default user id
                 */
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, 
                    ILogger.LL_FAILURE,
                    "OS: No such user as {0}.  Running as {1}", params);
            } catch (SecurityException e) {

                /*LogDoc
                 *
                 * @phase set user id
                 * @arg0 supplied user id in config
                 * @arg1 default user id
                 */
                mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                    ILogger.LL_FAILURE, 
                    "OS: Can't change process uid to {0}. Running as {1}", 
                    params);
            }
        }
    }

    private void initNT() {
    }

    /**
     * Stops the watchdog.  You need to call this if you want the
     * server to really shutdown, otherwise the watchdog will just
     * restart us.
     * <P>
     */
    public static void stop() {
        if (isUnix()) {
            shutdownUnix();
            Signal.send(LibC.getppid(), Signal.SIGTERM);
        } else {

            /*LogDoc
             *
             * @phase stop watchdog
             */
            CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER,
                ILogger.LL_INFO, 
                "OS: stop the NT watchdog!");
        }
    }

    /**
     * Stops this system.
     * <P>
     */
    public void shutdown() {
        if (isUnix()) {
            shutdownUnix();
        } else {
            shutdownNT();
        }
    }

    /**
     * Shutdown the unix system handlers
     * <P>
     */
    private static void shutdownUnix() {

        // Don't accidentally stop this thread
        //if (Thread.currentThread() != mSignalThread && mSignalThread != null) {
        //	mSignalThread.stop();
        //	mSignalThread = null;
        //}
		
        /* Don't release this signals to protect the process
         Signal.release(Signal.SIGHUP); 
         Signal.release(Signal.SIGTERM);
         Signal.release(Signal.SIGINT);
         */
    }

    /**
     * Shutdown the NT system handlers
     * <P>
     */
    private void shutdownNT() {
    }

    /**
     * Restart the server
     * <P>
     */
    public void restart() {

        /**
         if (isUnix()) {
         restartUnix();
         } else {
         restartNT();
         }
         **/
    }

    /**
     * Unix restart
     * <P>
     */
    private void restartUnix() {
        // Tell watch dog to restart us
        int ppid = LibC.getppid();

        Signal.send(ppid, Signal.SIGHUP);
    }

    /**
     * NT restart
     * <P>
     */
    private void restartNT() {
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * A universal routine to decide if we are Unix or something else.
     * This is mostly used for signal handling and uids.
     *
     * <P>
     * @return true if these OS the JavaVM is running on is some Unix varient
     */
    public static boolean isUnix() {
        // XXX What about MacOS?
        return (File.separatorChar == '/');
    }

    /**
     * Unix signal thread.  Sleep for a second and then check on the
     * signals we're interested in.  If one is set, do the right stuff
     */
    final class SignalThread extends Thread {

        /**
         * Signal thread constructor
         */
        public SignalThread() {
            super();
            super.setName("OsSignal-" + (Thread.activeCount() + 1));
        }

        /**
         * Check for signal changes every second
         */
        public void run() {
            while (true) {
                // Sleep for the interval and then check for caught signals
                // synchronized (Thread.this) {
                synchronized (this) {
                    try {
                        // Thread.this.wait(1000);
                        this.wait(1000);
                    } catch (InterruptedException e) {
                        // Not very interesting...
                    }
                }

                // wants us to exit?
                if (Signal.caught(Signal.SIGINT) > 0 ||
                    Signal.caught(Signal.SIGTERM) > 0) {

                    /*LogDoc
                     *
                     * @phase watchdog check
                     */
                    mLogger.log(ILogger.EV_SYSTEM, 
                        ILogger.S_OTHER, 
                        ILogger.LL_INFO,
                        "OS: Received shutdown signal");
                    SubsystemRegistry.getInstance().get("MAIN").shutdown();
                    return;
                }

                // Tell to restart us
                if (Signal.caught(Signal.SIGHUP) > 0) {

                    /*LogDoc
                     *
                     * @phase watchdog check
                     */
                    mLogger.log(ILogger.EV_SYSTEM, 
                        ILogger.S_OTHER, 
                        ILogger.LL_INFO,
                        "OS: Received restart signal");
                    restart();
                    return;
                }

            }
        }

    }
}


class SIGTERMListener extends SignalListener {
    private OsSubsystem mOS;
    public SIGTERMListener(OsSubsystem os) {
        mOS = os;
    }

    public void process() {
        System.out.println("SIGTERMListener process");
        // XXX - temp, should call shutdown
        System.exit(0);
        //PKIServer.getPKIServer().shutdown();
    }
}


class SIGINTListener extends SignalListener {
    private OsSubsystem mOS;
    public SIGINTListener(OsSubsystem os) {
        mOS = os;
    }

    public void process() {
        System.out.println("SIGINTListener process");
        // XXX - temp, should call shutdown
        System.exit(0);
        //PKIServer.getPKIServer().shutdown();
    }
}


class SIGHUPListener extends SignalListener {
    private OsSubsystem mOS;
    public SIGHUPListener(OsSubsystem os) {
        mOS = os;
    }

    public void process() {
        System.out.println("SIGHUPListener process");
        // XXX - temp, should call shutdown
        // System.exit(0);
        //PKIServer.getPKIServer().shutdown();
    }
}
