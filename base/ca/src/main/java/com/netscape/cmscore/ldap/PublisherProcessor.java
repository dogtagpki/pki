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
package com.netscape.cmscore.ldap;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.publish.Mapper;
import com.netscape.certsrv.publish.MapperPlugin;
import com.netscape.certsrv.publish.MapperProxy;
import com.netscape.certsrv.publish.Publisher;
import com.netscape.certsrv.publish.PublisherPlugin;
import com.netscape.certsrv.publish.PublisherProxy;
import com.netscape.certsrv.publish.RulePlugin;
import com.netscape.certsrv.request.RequestListener;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * Controls the publishing process from the top level. Maintains
 * a collection of Publishers , Mappers, and Publish Rules.
 */
public abstract class PublisherProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PublisherProcessor.class);

    public final static String PROP_CLASS = "class";
    public final static String PROP_IMPL = "impl";
    public final static String PROP_PLUGIN = "pluginName";
    public final static String PROP_INSTANCE = "instance";

    public final static String PROP_ENABLE = "enable";
    public final static String PROP_LDAP = "ldap";

    public Hashtable<String, PublisherPlugin> mPublisherPlugins = new Hashtable<>();
    public Hashtable<String, PublisherProxy> mPublisherInsts = new Hashtable<>();
    public Hashtable<String, MapperPlugin> mMapperPlugins = new Hashtable<>();
    public Hashtable<String, MapperProxy> mMapperInsts = new Hashtable<>();
    public Hashtable<String, RulePlugin> mRulePlugins = new Hashtable<>();
    public Hashtable<String, LdapRule> mRuleInsts = new Hashtable<>();

    // protected PublishRuleSet mRuleSet;

    protected LdapConnModule mLdapConnModule;

    protected PublishingConfig mConfig;
    protected LDAPPublishingConfig mLdapConfig;
    protected String mId;

    protected RequestListener requestListener;
    protected boolean mInited;

    public PublisherProcessor(String id) {
        mId = id;
    }

    public String getId() {
        return mId;
    }

    public void setId(String id) {
        mId = id;
    }

    public PublishingConfig getConfigStore() {
        return mConfig;
    }

    public RequestListener getRequestListener() {
        return requestListener;
    }

    public void setRequestListener(RequestListener requestListener) {
        this.requestListener = requestListener;
    }

    public void init(PublishingConfig config) throws EBaseException {

        mConfig = config;

        PublishingPublisherConfig publisherConfig = config.getPublisherConfig();
        PublishingPublisherPluginsConfig pluginsConfig = publisherConfig.getPublisherPluginsConfig();

        for (String id : pluginsConfig.getPluginIDs()) {
            logger.info("PublisherProcessor: Loading publisher plugin " + id);

            String pluginPath = pluginsConfig.getString(id + "." + PROP_CLASS);
            PublisherPlugin plugin = new PublisherPlugin(id, pluginPath);
            mPublisherPlugins.put(id, plugin);
        }

        PublishingPublisherInstancesConfig instancesConfig = publisherConfig.getPublisherInstancesConfig();

        for (String insName : instancesConfig.getInstanceIDs()) {
            logger.info("PublisherProcessor: Loading publisher instance " + insName);

            String implName = instancesConfig.getString(insName + "." + PROP_PLUGIN);
            PublisherPlugin plugin = mPublisherPlugins.get(implName);

            if (plugin == null) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PLUGIN_NOT_FIND", implName));
                throw new DBException(implName);
            }

            String className = plugin.getClassPath();

            // Instantiate and init the publisher.
            boolean isEnable = false;
            Publisher publisherInst = null;

            try {
                publisherInst = (Publisher) Class.forName(className).getDeclaredConstructor().newInstance();
                ConfigStore pConfig = instancesConfig.getPublisherInstanceConfig(insName);

                publisherInst.init(pConfig);
                isEnable = true;

            } catch (ClassNotFoundException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (IllegalAccessException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (InstantiationException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (Throwable e) {
                logger.warn("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_SKIP_PUBLISHER", insName, e.toString()), e);
                // Let the server continue if it is a
                // mis-configuration. But the instance
                // will be skipped. This give another
                // chance to the user to re-configure
                // the server via console.
            }

            if (publisherInst == null) {
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));
            }

            if (insName == null) {
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", insName));
            }

            mPublisherInsts.put(insName, new PublisherProxy(isEnable, publisherInst));
        }

        PublishingMapperConfig mapperConfig = config.getMapperConfig();

        ConfigStore c = mapperConfig.getSubStore(PROP_IMPL, ConfigStore.class);
        Enumeration<String> mImpls = c.getSubStoreNames().elements();
        while (mImpls.hasMoreElements()) {
            String id = mImpls.nextElement();
            logger.info("PublisherProcessor: Loading mapper plugin " + id);

            String pluginPath = c.getString(id + "." + PROP_CLASS);
            MapperPlugin plugin = new MapperPlugin(id, pluginPath);
            mMapperPlugins.put(id, plugin);
        }

        c = mapperConfig.getSubStore(PROP_INSTANCE, ConfigStore.class);
        Enumeration<String> instances = c.getSubStoreNames().elements();
        while (instances.hasMoreElements()) {
            String insName = instances.nextElement();
            logger.info("PublisherProcessor: Loading mapper instance " + insName);

            String implName = c.getString(insName + "." + PROP_PLUGIN);
            MapperPlugin plugin = mMapperPlugins.get(implName);

            if (plugin == null) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_MAPPER_NOT_FIND", implName));
                throw new DBException(implName);
            }

            String className = plugin.getClassPath();

            // Instantiate and init the mapper
            boolean isEnable = false;
            Mapper mapperInst = null;

            try {
                mapperInst = (Mapper) Class.forName(className).getDeclaredConstructor().newInstance();
                ConfigStore mConfig = c.getSubStore(insName, ConfigStore.class);

                mapperInst.init(mConfig);
                isEnable = true;

            } catch (ClassNotFoundException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (IllegalAccessException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (InstantiationException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (Throwable e) {
                logger.warn("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_SKIP_MAPPER", insName, e.toString()), e);
                // Let the server continue if it is a
                // mis-configuration. But the instance
                // will be skipped. This give another
                // chance to the user to re-configure
                // the server via console.
            }

            if (mapperInst == null) {
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));
            }

            mMapperInsts.put(insName, new MapperProxy(isEnable, mapperInst));
        }

        PublishingRuleConfig ruleConfig = config.getRuleConfig();

        c = ruleConfig.getSubStore(PROP_IMPL, ConfigStore.class);
        mImpls = c.getSubStoreNames().elements();
        while (mImpls.hasMoreElements()) {
            String id = mImpls.nextElement();
            logger.info("PublisherProcessor: Loading rule plugin " + id);

            String pluginPath = c.getString(id + "." + PROP_CLASS);
            RulePlugin plugin = new RulePlugin(id, pluginPath);

            mRulePlugins.put(id, plugin);
        }

        c = ruleConfig.getSubStore(PROP_INSTANCE, ConfigStore.class);
        instances = c.getSubStoreNames().elements();
        while (instances.hasMoreElements()) {
            String insName = instances.nextElement();
            logger.info("PublisherProcessor: Loading rule instance " + insName);

            String implName = c.getString(insName + "." + PROP_PLUGIN);
            RulePlugin plugin = mRulePlugins.get(implName);

            if (plugin == null) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_RULE_NOT_FIND", implName));
                throw new DBException(implName);
            }

            String className = plugin.getClassPath();

            // Instantiate and init the rule
            ConfigStore mConfig = null;

            try {
                LdapRule ruleInst = null;

                ruleInst = (LdapRule) Class.forName(className).getDeclaredConstructor().newInstance();
                mConfig = c.getSubStore(insName, ConfigStore.class);
                ruleInst.init(mMapperInsts, mPublisherInsts, mConfig);
                ruleInst.setInstanceName(insName);

                mRuleInsts.put(insName, ruleInst);

            } catch (ClassNotFoundException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (IllegalAccessException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (InstantiationException e) {
                logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PUBLISHER_INIT_FAILED", e.toString()), e);
                throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));

            } catch (Throwable e) {
                if (mConfig == null) {
                    throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className));
                }
                mConfig.putString(LdapRule.PROP_ENABLE, "false");
                logger.warn("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_SKIP_RULE", insName, e.toString()), e);
                // Let the server continue if it is a
                // mis-configuration. But the instance
                // will be skipped. This give another
                // chance to the user to re-configure
                // the server via console.
            }
        }

        startup();
        mInited = true;
    }

    /**
     * Returns LdapConnModule belonging to this Processor.
     *
     * @return LdapConnModule.
     */
    public LdapConnModule getLdapConnModule() {
        return mLdapConnModule;
    }

    /**
     * Sets the LdapConnModule belonging to this Processor.
     *
     * @param m LdapConnModule.
     */
    public void setLdapConnModule(LdapConnModule m) {
        mLdapConnModule = m;
    }

    /**
     * init ldap connection
     */
    private void initLdapConn() throws EBaseException {
        try {
            if (mLdapConfig != null && mLdapConfig.size() > 0) {
                mLdapConnModule = new LdapConnModule();
                mLdapConnModule.init(mLdapConfig);
                logger.debug("LdapPublishing connection inited");
            } else {
                logger.error("PublisherProcessor: No Ldap Module configuration found");
                throw new DBException(
                        CMS.getUserMessage("CMS_LDAP_NO_LDAP_PUBLISH_CONFIG_FOUND"));
            }

        } catch (DBException e) {
            logger.error("PublisherProcessor: Ldap Publishing Module failed: " + e.getMessage(), e);
            throw new DBException(CMS.getUserMessage("CMS_LDAP_INIT_LDAP_PUBLISH_MODULE_FAILED", e.toString()));
        }
    }

    public void startup() throws EBaseException {
        logger.debug("PublisherProcessor: startup()");
        mLdapConfig = mConfig.getLDAPPublishingConfig();
        if (mLdapConfig.isEnabled()) {
            logger.debug("PublisherProcessor: about to initLdapConn");
            initLdapConn();
        } else {
            logger.debug("No LdapPublishing enabled");
        }
    }

    public void shutdown() {
        logger.debug("Shuting down publishing.");
        try {
            if (mLdapConnModule != null) {
                mLdapConnModule.getLdapConnFactory().reset();
            }
        } catch (DBException e) {
            // ignore
            logger.warn("Unable to shutdown publishing: " + e.getMessage(), e);
        }
    }

    /**
     * Returns Hashtable of rule plugins.
     */
    public Hashtable<String, RulePlugin> getRulePlugins() {
        return mRulePlugins;
    }

    /**
     * Returns Hashtable of rule instances.
     */
    public Hashtable<String, LdapRule> getRuleInsts() {
        return mRuleInsts;
    }

    /**
     * Returns Hashtable of mapper plugins.
     */
    public Hashtable<String, MapperPlugin> getMapperPlugins() {
        return mMapperPlugins;
    }

    /**
     * Returns Hashtable of publisher plugins.
     */
    public Hashtable<String, PublisherPlugin> getPublisherPlugins() {
        return mPublisherPlugins;
    }

    /**
     * Returns Hashtable of rule mapper instances.
     */
    public Hashtable<String, MapperProxy> getMapperInsts() {
        return mMapperInsts;
    }

    /**
     * Returns Hashtable of rule publisher instances.
     */
    public Hashtable<String, PublisherProxy> getPublisherInsts() {
        return mPublisherInsts;
    }

    /**
     * Returns list of rules based on publishing type.
     *
     * certType can be client,server,ca,crl,smime
     *
     * @param publishingType Type for which to retrieve rule list.
     */
    public Enumeration<LdapRule> getRules(String publishingType) {

        logger.info("PublisherProcessor: Getting " + publishingType + " publishing rules");

        Vector<LdapRule> rules = new Vector<>();
        Enumeration<String> e = mRuleInsts.keys();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name == null) {
                logger.warn("Missing publishing rule name");
                return null;
            }

            logger.info("PublisherProcessor: - name: " + name);

            //this is the only rule we support now
            LdapRule rule = mRuleInsts.get(name);

            logger.info("PublisherProcessor:   enabled: " + rule.enabled());
            if (!rule.enabled()) {
                continue;
            }

            logger.info("PublisherProcessor:   type: " + rule.getType());
            if (!publishingType.equals(rule.getType())) {
                continue;
            }

            // check if the predicate match
            LdapExpression exp = rule.getPredicate();
            logger.info("PublisherProcessor:   predicate: " + exp);

            try {
                SessionContext sc = SessionContext.getContext();

                if (exp != null && !exp.evaluate(sc)) {
                    logger.info("PublisherProcessor:   predicate => false");
                    continue;
                }

            } catch (Exception ex) {
                logger.warn("PublisherProcessor: " + ex.getMessage(), ex);
            }

            rules.addElement(rule);
        }

        return rules.elements();
    }

    /**
     * Returns list of rules based on publishing type and publishing request.
     *
     * @param publishingType Type for which to retrieve rule list.
     * @param req Corresponding publish request.
     */
    public Enumeration<LdapRule> getRules(String publishingType, Request req) {

        if (req == null) {
            return getRules(publishingType);
        }

        logger.info("PublisherProcessor: Getting " + publishingType + " publishing rules for request " + req.getRequestId().toHexString());

        Vector<LdapRule> rules = new Vector<>();
        Enumeration<LdapRule> e = mRuleInsts.elements();

        while (e.hasMoreElements()) {
            //this is the only rule we support now
            LdapRule rule = e.nextElement();
            logger.info("PublisherProcessor: - name: " + rule.getInstanceName());

            logger.debug("PublisherProcessor:   enabled: " + rule.enabled());
            if (!rule.enabled()) {
                logger.info("PublisherProcessor:   rule disabled");
                continue;
            }

            logger.debug("PublisherProcessor:   type: " + rule.getType());
            if (!publishingType.equals(rule.getType())) {
                logger.info("PublisherProcessor:   type doesn't match");
                continue;
            }

            // check if the predicate match
            LdapExpression exp = rule.getPredicate();
            logger.debug("PublisherProcessor:   predicate: " + exp);

            try {
                if (exp != null && !exp.evaluate(req)) {
                    logger.info("PublisherProcessor:   predicate => false");
                    continue;
                }

            } catch (Exception ex) {
                logger.warn("PublisherProcessor: " + ex.getMessage(), ex);
            }

            rules.addElement(rule);
        }

        return rules.elements();
    }

    // public PublishRuleSet getPublishRuleSet() {
    //     return mRuleSet;
    // }

    /**
     * Returns mapper initial default parameters.
     *
     * @param implName name of MapperPlugin.
     */
    public Vector<String> getMapperDefaultParams(String implName) throws
            DBException {
        // is this a registered implname?
        MapperPlugin plugin = mMapperPlugins.get(implName);

        if (plugin == null) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_MAPPER_NOT_FIND", implName));
            throw new DBException(implName);
        }

        // XXX can find an instance of this plugin in existing
        // mapper instances to avoid instantiation just for this.

        // a temporary instance
        Mapper mapperInst = null;
        String className = plugin.getClassPath();

        try {
            mapperInst = (Mapper) Class.forName(className).getDeclaredConstructor().newInstance();
            Vector<String> v = mapperInst.getDefaultParams();

            return v;

        } catch (Exception e) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_NEW_MAPPER", e.toString()), e);
            throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className), e);
        }
    }

    /**
     * Returns mapper current instance parameters.
     *
     * @param insName name of MapperProxy.
     * @exception DBException failed due to Ldap error.
     */
    public Vector<String> getMapperInstanceParams(String insName) throws
            DBException {
        Mapper mapperInst = null;
        MapperProxy proxy = mMapperInsts.get(insName);

        if (proxy == null) {
            return null;
        }
        mapperInst = proxy.getMapper();
        if (mapperInst == null) {
            return null;
        }
        Vector<String> v = mapperInst.getInstanceParams();

        return v;
    }

    /**
     * Returns publisher initial default parameters.
     *
     * @param implName name of PublisherPlugin.
     * @exception DBException failed due to Ldap error.
     */
    public Vector<String> getPublisherDefaultParams(String implName) throws
            DBException {
        // is this a registered implname?
        PublisherPlugin plugin = mPublisherPlugins.get(implName);

        if (plugin == null) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_PLUGIN_NOT_FIND", implName));
            throw new DBException(implName);
        }

        // XXX can find an instance of this plugin in existing
        // publisher instantces to avoid instantiation just for this.

        // a temporary instance
        Publisher publisherInst = null;
        String className = plugin.getClassPath();

        try {
            publisherInst = (Publisher) Class.forName(className).getDeclaredConstructor().newInstance();
            Vector<String> v = publisherInst.getDefaultParams();

            return v;

        } catch (Exception e) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_NEW_PUBLISHER", e.toString()), e);
            throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className), e);
        }
    }

    /**
     * Returns true if MapperInstance is enabled.
     *
     * @param insName name of MapperProxy.
     * @return true if enabled. false if disabled.
     */
    public boolean isMapperInstanceEnable(String insName) {
        MapperProxy proxy = mMapperInsts.get(insName);

        if (proxy == null) {
            return false;
        }
        return proxy.isEnable();
    }

    /**
     * Returns Mapper instance that is currently active.
     *
     * @param insName name of MapperProxy.
     * @return instance of Mapper.
     */
    public Mapper getActiveMapperInstance(String insName) {
        MapperProxy proxy = mMapperInsts.get(insName);

        if (proxy == null)
            return null;
        return proxy.isEnable() ? proxy.getMapper() : null;
    }

    /**
     * Returns Mapper instance based on name of MapperProxy.
     *
     * @param insName name of MapperProxy.
     * @return instance of Mapper.
     */
    public Mapper getMapperInstance(String insName) {
        MapperProxy proxy = mMapperInsts.get(insName);

        if (proxy == null)
            return null;
        return proxy.getMapper();
    }

    /**
     * Returns true publisher instance is currently enabled.
     *
     * @param insName name of PublisherProxy.
     * @return true if enabled.
     */
    public boolean isPublisherInstanceEnable(String insName) {
        PublisherProxy proxy = mPublisherInsts.get(insName);

        if (proxy == null) {
            return false;
        }
        return proxy.isEnable();
    }

    /**
     * Returns Publisher instance that is currently active.
     *
     * @param insName name of PublisherProxy.
     * @return instance of Publisher.
     */
    public Publisher getActivePublisherInstance(String insName) {
        PublisherProxy proxy = mPublisherInsts.get(insName);

        if (proxy == null) {
            return null;
        }
        return proxy.isEnable() ? proxy.getPublisher() : null;
    }

    /**
     * Returns Publisher instance.
     *
     * @param insName name of PublisherProxy.
     * @return instance of Publisher.
     */
    public Publisher getPublisherInstance(String insName) {
        PublisherProxy proxy = mPublisherInsts.get(insName);

        if (proxy == null) {
            return null;
        }
        return proxy.getPublisher();
    }

    /**
     * Returns Vector of PublisherIntance's current instance parameters.
     *
     * @param insName name of PublisherProxy.
     * @return Vector of current instance parameters.
     */
    public Vector<String> getPublisherInstanceParams(String insName) throws
            DBException {
        Publisher publisherInst = getPublisherInstance(insName);

        if (publisherInst == null) {
            return null;
        }
        Vector<String> v = publisherInst.getInstanceParams();

        return v;
    }

    /**
     * Returns Vector of RulePlugin's initial default parameters.
     *
     * @param implName name of RulePlugin.
     * @return Vector of initial default parameters.
     * @exception DBException failed due to Ldap error.
     */
    public Vector<String> getRuleDefaultParams(String implName) throws
            DBException {
        // is this a registered implname?
        RulePlugin plugin = mRulePlugins.get(implName);

        if (plugin == null) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_RULE_NOT_FIND", implName));
            throw new DBException(implName);
        }

        // XXX can find an instance of this plugin in existing
        // rule instantces to avoid instantiation just for this.

        // a temporary instance
        LdapRule ruleInst = null;
        String className = plugin.getClassPath();

        try {
            ruleInst = (LdapRule) Class.forName(className).getDeclaredConstructor().newInstance();

            Vector<String> v = ruleInst.getDefaultParams();

            return v;

        } catch (Exception e) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_NEW_RULE", e.toString()), e);
            throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className), e);
        }
    }

    /**
     * Returns Vector of RulePlugin's current instance parameters.
     *
     * @param implName name of RulePlugin.
     * @return Vector of current instance parameters.
     * @exception DBException failed due to Ldap error.
     */
    public Vector<String> getRuleInstanceParams(String implName) throws
            DBException {
        // is this a registered implname?
        RulePlugin plugin = mRulePlugins.get(implName);

        if (plugin == null) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_RULE_NOT_FIND", implName));
            throw new DBException(implName);
        }

        // XXX can find an instance of this plugin in existing
        // rule instantces to avoid instantiation just for this.

        // a temporary instance
        LdapRule ruleInst = null;
        String className = plugin.getClassPath();

        try {
            ruleInst = (LdapRule) Class.forName(className).getDeclaredConstructor().newInstance();
            Vector<String> v = ruleInst.getInstanceParams();

            return v;

        } catch (Exception e) {
            logger.error("PublisherProcessor: " + CMS.getLogMessage("CMSCORE_LDAP_NO_NEW_RULE", e.toString()), e);
            throw new DBException(CMS.getUserMessage("CMS_LDAP_FAIL_LOAD_CLASS", className), e);
        }
    }

    /**
     * Return true if Ldap is enabled.
     *
     * @return true if Ldap is enabled,otherwise false.
     */
    public boolean ldapEnabled() {
        try {
            return mInited && mLdapConfig.isEnabled();
        } catch (EBaseException e) {
            return false;
        }
    }
}
