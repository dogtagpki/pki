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
package com.netscape.cmscore.logging;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogQueue;
import com.netscape.certsrv.logging.ILogSubsystem;
import com.netscape.certsrv.logging.LogPlugin;
import com.netscape.cmscore.util.Debug;

/**
 * A class represents a log subsystem.
 * <P>
 *
 * @author thomask
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class LogSubsystem implements ILogSubsystem {

    private static LogSubsystem mInstance = new LogSubsystem();
    private static ILogQueue mLogQueue = LogQueue.getLogQueue();
    private IConfigStore mConfig = null;

    public static final String PROP_LOGGING = "log";

    public static final String ID = "log";

    public static final String PROP_CLASS = "class";
    public static final String PROP_IMPL = "impl";
    public static final String PROP_PLUGIN = "pluginName";
    public static final String PROP_INSTANCE = "instance";

    public Hashtable<String, LogPlugin> mLogPlugins = new Hashtable<String, LogPlugin>();
    public Hashtable<String, ILogEventListener> mLogInsts = new Hashtable<String, ILogEventListener>();

    /**
     * Constructs a log subsystem.
     */
    private LogSubsystem() {
    }

    public String getId() {
        return ID;
    }

    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Initializes the log subsystem.
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mConfig = config;
        mLogQueue.init();

        // load log plugin implementation
        IConfigStore c = config.getSubStore(PROP_IMPL);
        Enumeration<String> mImpls = c.getSubStoreNames();

        while (mImpls.hasMoreElements()) {
            String id = mImpls.nextElement();
            String pluginPath = c.getString(id + "." + PROP_CLASS);
            LogPlugin plugin = new LogPlugin(id, pluginPath);

            mLogPlugins.put(id, plugin);
        }
        if (Debug.ON)
            Debug.trace("loaded logger plugins");

        // load log instances
        c = config.getSubStore(PROP_INSTANCE);
        Enumeration<String> instances = c.getSubStoreNames();

        while (instances.hasMoreElements()) {
            String insName = instances.nextElement();
            String implName = c.getString(insName + "." +
                    PROP_PLUGIN);
            LogPlugin plugin =
                    mLogPlugins.get(implName);

            if (plugin == null) {
                throw new EBaseException(implName);
            }
            String className = plugin.getClassPath();
            // Instantiate and init the log listener.
            ILogEventListener logInst = null;

            try {
                logInst = (ILogEventListener)
                        Class.forName(className).newInstance();
                IConfigStore pConfig =
                        c.getSubStore(insName);

                logInst.init(this, pConfig);
                // for view from console

            } catch (ClassNotFoundException e) {
                throw new EBaseException(insName + ":Failed to instantiate class " + className);

            } catch (IllegalAccessException e) {
                throw new EBaseException(insName + ":Failed to instantiate class " + className);

            } catch (InstantiationException e) {
                throw new EBaseException(insName + ":Failed to instantiate class " + className);

            } catch (Throwable e) {
                e.printStackTrace();
                throw new EBaseException(insName
                        + ":Failed to instantiate class " + className + " error: " + e.getMessage());
            }

            if (insName == null) {
                throw new EBaseException("Failed to instantiate class " + insName);
            }

            // add log instance to list.
            mLogInsts.put(insName, logInst);
            if (Debug.ON)
                Debug.trace("loaded log instance " + insName + " impl " + implName);
        }

    }

    public void startup() throws EBaseException {
        Debug.trace("entering LogSubsystem.startup()");
        Enumeration<String> enum1 = mLogInsts.keys();

        while (enum1.hasMoreElements()) {
            String instName = enum1.nextElement();

            Debug.trace("about to call inst=" + instName + " in LogSubsystem.startup()");
            ILogEventListener inst = mLogInsts.get(instName);

            inst.startup();
        }
    }

    /**
     * Stops this subsystem.
     * <P>
     */
    public void shutdown() {
        mLogQueue.shutdown();
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
     * Retrieves singleton: the LogSubsystem.
     */
    public static LogSubsystem getInstance() {
        return mInstance;
    }

    /**
     * Retrieves LogQueue.
     */
    public static ILogQueue getLogQueue() {
        return mLogQueue;
    }

    public String getLogPluginName(ILogEventListener log) {
        IConfigStore cs = log.getConfigStore();
        if (cs == null) {
            return "";
        }
        try {
            return cs.getString("pluginName", "");
        } catch (EBaseException e) {
            e.printStackTrace();
            return "";
        }
    }

    /**
     * Retrieve log instance by it's name
     */
    public ILogEventListener getLogInstance(String insName) {
        return mLogInsts.get(insName);
    }

    public Hashtable<String, LogPlugin> getLogPlugins() {
        return mLogPlugins;
    }

    public Hashtable<String, ILogEventListener> getLogInsts() {
        return mLogInsts;
    }

    public Vector<String> getLogDefaultParams(String implName) throws
            ELogException {
        // is this a registered implname?
        LogPlugin plugin = mLogPlugins.get(implName);

        if (plugin == null) {
            throw new ELogException(implName);
        }

        // a temporary instance
        ILogEventListener LogInst = null;
        String className = plugin.getClassPath();

        try {
            LogInst = (ILogEventListener)
                    Class.forName(className).newInstance();
            Vector<String> v = LogInst.getDefaultParams();

            return v;
        } catch (InstantiationException e) {
            throw new ELogException(
                    CMS.getUserMessage("CMS_LOG_LOAD_CLASS_FAIL", className));
        } catch (ClassNotFoundException e) {
            throw new ELogException(
                    CMS.getUserMessage("CMS_LOG_LOAD_CLASS_FAIL", className));
        } catch (IllegalAccessException e) {
            throw new ELogException(
                    CMS.getUserMessage("CMS_LOG_LOAD_CLASS_FAIL", className));
        }
    }

    public Vector<String> getLogInstanceParams(String insName) throws
            ELogException {
        ILogEventListener logInst = getLogInstance(insName);

        if (logInst == null) {
            return null;
        }
        Vector<String> v = logInst.getInstanceParams();

        return v;
    }
}
