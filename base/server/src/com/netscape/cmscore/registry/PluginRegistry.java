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
package com.netscape.cmscore.registry;

import java.io.File;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.registry.ERegistryException;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;

/**
 * This represents the registry subsystem that manages
 * mulitple types of plugin information.
 *
 * The plugin information includes id, name,
 * classname, and description.
 */
public class PluginRegistry {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PluginRegistry.class);

    public static final String ID = "registry";

    private static final String PROP_TYPES = "types";
    private static final String PROP_IDS = "ids";
    private static final String PROP_NAME = "name";
    private static final String PROP_DESC = "desc";
    private static final String PROP_CLASSPATH = "class";
    private static final String PROP_FILE = "file";

    private IConfigStore mConfig = null;
    private PropConfigStore fileConfig;
    private Hashtable<String, Hashtable<String, IPluginInfo>> mTypes =
            new Hashtable<String, Hashtable<String, IPluginInfo>>();

    public PluginRegistry() {
    }

    /**
     * Initializes this subsystem with the given configuration
     * store.
     * <P>
     * @param config configuration store
     *
     * @exception EBaseException failed to initialize
     */
    public void init(IConfigStore config, String defaultRegistryFile)
            throws Exception {

        mConfig = config;

        String registryFile = config.getString(PROP_FILE, defaultRegistryFile);
        logger.info("PluginRegistry: Loading plugin registry from " + registryFile);

        File f = new File(registryFile);
        f.createNewFile();

        FileConfigStore storage = new FileConfigStore(registryFile);
        fileConfig = new PropConfigStore(storage);
        fileConfig.load();

        String types = fileConfig.getString(PROP_TYPES, null);

        if (types == null) {
            return;
        }

        StringTokenizer st = new StringTokenizer(types, ",");

        while (st.hasMoreTokens()) {
            String type = st.nextToken();
            logger.info("PluginRegistry: " + type + ":");

            loadPlugins(config, type);
        }
    }

    /**
     * Load plugins of the given type.
     */
    public void loadPlugins(IConfigStore config, String type)
            throws EBaseException {

        String ids_str = fileConfig.getString(type + "." + PROP_IDS, null);

        if (ids_str == null) {
            return;
        }

        StringTokenizer st = new StringTokenizer(ids_str, ",");

        while (st.hasMoreTokens()) {
            String id = st.nextToken();
            logger.info("PluginRegistry: - " + id);

            loadPlugin(config, type, id);
        }
    }

    public IPluginInfo createPluginInfo(String name, String desc, String classPath) {
        return new PluginInfo(name, desc, classPath);
    }

    /**
     * Load plugins of the given type.
     */
    public void loadPlugin(IConfigStore config, String type, String id)
            throws EBaseException {

        String name = fileConfig.getString(type + "." + id + "." + PROP_NAME, null);
        String desc = fileConfig.getString(type + "." + id + "." + PROP_DESC, null);
        String classpath = fileConfig.getString(type + "." + id + "." + PROP_CLASSPATH, null);

        PluginInfo info = new PluginInfo(name, desc, classpath);

        addPluginInfo(type, id, info, 0);
    }

    public void removePluginInfo(String type, String id)
            throws ERegistryException {
        Hashtable<String, IPluginInfo> plugins = mTypes.get(type);
        if (plugins == null)
            return;
        plugins.remove(id);
        Locale locale = Locale.getDefault();
        rebuildConfigStore(locale);
    }

    public void addPluginInfo(String type, String id, IPluginInfo info)
            throws ERegistryException {
        addPluginInfo(type, id, info, 1);
    }

    public void addPluginInfo(String type, String id, IPluginInfo info, int saveConfig)
            throws ERegistryException {

        Hashtable<String, IPluginInfo> plugins = mTypes.get(type);

        if (plugins == null) {
            plugins = new Hashtable<String, IPluginInfo>();
            mTypes.put(type, plugins);
        }

        Locale locale = Locale.getDefault();

        logger.debug("PluginRegistry: Added plugin " + type + " " + id + " " +
                info.getName(locale) + " " + info.getDescription(locale) + " " +
                info.getClassName());
        plugins.put(id, info);

        // rebuild configuration store
        if (saveConfig == 1) {
            rebuildConfigStore(locale);
        }
    }

    public void rebuildConfigStore(Locale locale)
            throws ERegistryException {

        Enumeration<String> types = mTypes.keys();
        StringBuffer typesBuf = new StringBuffer();

        while (types.hasMoreElements()) {
            String type = types.nextElement();

            typesBuf.append(type);
            if (types.hasMoreElements()) {
                typesBuf.append(",");
            }

            Hashtable<String, IPluginInfo> mPlugins = mTypes.get(type);
            StringBuffer idsBuf = new StringBuffer();
            Enumeration<String> plugins = mPlugins.keys();

            while (plugins.hasMoreElements()) {
                String id = plugins.nextElement();

                idsBuf.append(id);
                if (plugins.hasMoreElements()) {
                    idsBuf.append(",");
                }

                IPluginInfo plugin = mPlugins.get(id);

                fileConfig.putString(type + "." + id + ".class",
                        plugin.getClassName());
                fileConfig.putString(type + "." + id + ".name",
                        plugin.getName(locale));
                fileConfig.putString(type + "." + id + ".desc",
                        plugin.getDescription(locale));
            }
            fileConfig.putString(type + ".ids", idsBuf.toString());
        }

        fileConfig.putString("types", typesBuf.toString());

        File file = ((FileConfigStore) fileConfig.getStorage()).getFile();

        try {
            logger.info("PluginRegistry: Updating " + file.getAbsolutePath());
            fileConfig.commit(false);

        } catch (Exception e) {
            logger.warn("Unable to update " + file.getAbsolutePath() + ": " + e.getMessage(), e);
        }
    }

    /**
     * Notifies this subsystem if owner is in running mode.
     */
    public void startup() throws EBaseException {
        logger.debug("RegistrySubsystem: startup");
    }

    /**
     * Stops this system. The owner may call shutdown
     * anytime after initialization.
     * <P>
     */
    public void shutdown() {
        mTypes.clear();
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
     * Returns handle to the registry configuration file.
     */
    public IConfigStore getFileConfigStore() {
        return fileConfig;
    }

    /**
     * Returns all type names.
     */
    public Enumeration<String> getTypeNames() {
        return mTypes.keys();
    }

    /**
     * Returns a list of identifiers of the given type.
     */
    public Enumeration<String> getIds(String type) {
        Hashtable<String, IPluginInfo> plugins = mTypes.get(type);

        if (plugins == null)
            return null;
        return plugins.keys();
    }

    /**
     * Retrieves the plugin information.
     */
    public IPluginInfo getPluginInfo(String type, String id) {
        Hashtable<String, IPluginInfo> plugins = mTypes.get(type);

        if (plugins == null)
            return null;
        return plugins.get(id);
    }

}
