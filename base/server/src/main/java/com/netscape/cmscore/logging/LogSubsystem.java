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

import java.util.Collection;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.logging.ELogException;
import com.netscape.certsrv.logging.ILogEventListener;
import com.netscape.certsrv.logging.ILogQueue;
import com.netscape.certsrv.logging.ILogSubsystem;
import com.netscape.certsrv.logging.LogPlugin;
import com.netscape.cms.logging.LogQueue;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a log subsystem.
 * <P>
 *
 * @author thomask
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class LogSubsystem implements ILogSubsystem {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LogSubsystem.class);

    private static LogSubsystem mInstance = new LogSubsystem();
    private static ILogQueue mLogQueue = LogQueue.getLogQueue();
    private IConfigStore mConfig = null;

    public static final String PROP_LOGGING = "log";

    public static final String ID = "log";

    public static final String PROP_CLASS = "class";
    public static final String PROP_IMPL = "impl";
    public static final String PROP_PLUGIN = "pluginName";
    public static final String PROP_INSTANCE = "instance";

    public Hashtable<String, LogPlugin> mLogPlugins = new Hashtable<>();
    public Hashtable<String, ILogEventListener> mLogInsts = new Hashtable<>();
    public Set<String> auditEvents = new TreeSet<>();

    /**
     * Constructs a log subsystem.
     */
    private LogSubsystem() {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void setId(String id) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_OPERATION"));
    }

    /**
     * Initializes the log subsystem.
     * <P>
     * @param config configuration store
     */
    @Override
    public void init(IConfigStore config)
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
        logger.trace("loaded logger plugins");

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
                logInst = (ILogEventListener) Class.forName(className).getDeclaredConstructor().newInstance();
                IConfigStore pConfig =
                        c.getSubStore(insName);

                logInst.init(this, pConfig);
                // for view from console

            } catch (EBaseException e) {
                throw e;

            } catch (Exception e) {
                throw new EBaseException(insName + ": Unable to create " + className + ": " + e.getMessage(), e);
            }

            // add log instance to list.
            mLogInsts.put(insName, logInst);
            logger.trace("loaded log instance " + insName + " impl " + implName);
        }

        // load audit events from audit-events.properties
        ResourceBundle rb = ResourceBundle.getBundle("audit-events");
        Pattern value_pattern = Pattern.compile("^<type=(.*)>:.*");

        for (String name : rb.keySet()) {

            String value = rb.getString(name);

            Matcher value_matcher = value_pattern.matcher(value);
            if (!value_matcher.matches()) {
                continue;
            }

            String event = value_matcher.group(1);

            auditEvents.add(event.trim());
        }
    }

    public Collection<String> getAuditEvents() {
        return auditEvents;
    }

    @Override
    public void startup() throws EBaseException {
        logger.trace("entering LogSubsystem.startup()");
        Enumeration<String> enum1 = mLogInsts.keys();

        while (enum1.hasMoreElements()) {
            String instName = enum1.nextElement();

            logger.trace("about to call inst=" + instName + " in LogSubsystem.startup()");
            ILogEventListener inst = mLogInsts.get(instName);

            inst.startup();
        }
    }

    /**
     * Stops this subsystem.
     * <P>
     */
    @Override
    public void shutdown() {
        mLogQueue.shutdown();
    }

    /**
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    @Override
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Retrieves singleton: the LogSubsystem.
     */
    public static LogSubsystem getInstance() {
        return mInstance;
    }

    @Override
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
    @Override
    public ILogEventListener getLogInstance(String insName) {
        return mLogInsts.get(insName);
    }

    @Override
    public Hashtable<String, LogPlugin> getLogPlugins() {
        return mLogPlugins;
    }

    @Override
    public Hashtable<String, ILogEventListener> getLogInsts() {
        return mLogInsts;
    }

    @Override
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
            LogInst = (ILogEventListener) Class.forName(className).getDeclaredConstructor().newInstance();
            Vector<String> v = LogInst.getDefaultParams();

            return v;

        } catch (Exception e) {
            throw new ELogException(CMS.getUserMessage("CMS_LOG_LOAD_CLASS_FAIL", className), e);
        }
    }

    @Override
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
