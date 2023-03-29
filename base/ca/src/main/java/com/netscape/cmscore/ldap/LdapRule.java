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

import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.publish.MapperProxy;
import com.netscape.certsrv.publish.PublisherProxy;
import com.netscape.cmscore.base.ConfigStore;

/**
 * The publishing rule which associates a Publisher with a Mapper.
 */
public class LdapRule implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapRule.class);

    public final static String PROP_PREDICATE = "predicate";
    public final static String PROP_ENABLE = "enable";
    public final static String PROP_IMPLNAME = "implName";

    public final static String PROP_MAPPER = "mapper";
    public final static String PROP_PUBLISHER = "publisher";
    public final static String PROP_TYPE = "type";

    public final static String NOMAPPER = "<NONE>";

    private ConfigStore mConfig;
    protected LdapExpression mFilterExp = null;
    private String mInstanceName = null;

    private static String[] epi_params = null; // extendedpluginInfo

    public ConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
    public String[] getExtendedPluginInfo() {
        //dont know why it's null here.
        //if (mProcessor == null) logger.warn("p null");

        logger.trace("LdapRule: getExtendedPluginInfo() - returning epi_params:");
        for (int i = 0; i < epi_params.length; i++) {
            logger.trace("[" + i + "]  " + epi_params[i]);
        }

        return epi_params;
    }

    /**
     * Initialize the plugin.
     *
     * @exception EBaseException Initialization failed.
     */
    public void init(
            Hashtable<String, MapperProxy> mappers,
            Hashtable<String, PublisherProxy> publishers,
            ConfigStore config) throws EBaseException {
        mConfig = config;

        StringBuffer map = new StringBuffer();
        map.append(NOMAPPER);
        for (String name : mappers.keySet()) {
            map.append("," + name);
        }

        StringBuffer publish = new StringBuffer();
        for (String name : publishers.keySet()) {
            publish.append("," + name);
        }

        epi_params = new String[] {
                "type;choice(cacert,crl, certs);The publishing object type",
                "mapper;choice("
                        + map.toString() + ");Use the mapper to find the ldap dn \nto publish the certificate or crl",
                "publisher;choice("
                        + publish.toString() + ");Use the publisher to publish the certificate or crl a directory etc",
                "enable;boolean;Enable this publishing rule",
                "predicate;string;Filter describing when this publishing rule shoule be used"
        };

        // Read the predicate expression if any associated
        // with the rule
        String exp = config.getString(PROP_PREDICATE, null);
        logger.info("LdapRule: predicate: " + exp);

        if (exp != null) {
            exp = exp.trim();
        }

        if (exp != null && exp.length() > 0) {
            LdapExpression filterExp = LdapPredicateParser.parse(exp);
            setPredicate(filterExp);
        }

        //if (mProcessor == null) System.out.println("null");
    }

    /**
     * The init method in ILdapPlugin
     * It can not set set mapper,publisher choice for console dynamicly
     * Should not use this method to init.
     */
    public void init(ConfigStore config) throws EBaseException {
        mConfig = config;

        epi_params = new String[] {
                "type;choice(cacert, crl, certs);The publishing object type",
                "mapper;choice(null,LdapUserCertMap,LdapServerCertMap,LdapCrlMap,LdapCaCertMap);Use the mapper to find the ldap dn to publish the certificate or crl",
                "publisher;choice(LdapUserCertPublisher,LdapServerCertPublisher,LdapCrlPublisher,LdapCaCertPublisher);Use the publisher to publish the certificate or crl a directory etc",
                "enable;boolean;",
                "predicate;string;"
        };

        // Read the predicate expression if any associated
        // with the rule
        String exp = config.getString(PROP_PREDICATE, null);
        logger.info("LdapRule: predicate: " + exp);

        if (exp != null) {
            exp = exp.trim();
        }

        if (exp != null && exp.length() > 0) {
            LdapExpression filterExp = LdapPredicateParser.parse(exp);
            setPredicate(filterExp);
        }
    }

    /**
     * Returns the implementation name.
     */
    public String getImplName() {
        return "LdapRule";
    }

    /**
     * Returns the description of the LDAP publisher.
     */
    public String getDescription() {
        return "LdapRule";
    }

    /**
     * Sets the instance name.
     */
    public void setInstanceName(String insName) {
        mInstanceName = insName;
    }

    /**
     * Returns the instance name.
     */
    public String getInstanceName() {
        return mInstanceName;
    }

    /**
     * Returns the current instance parameters.
     */
    public Vector<String> getInstanceParams() {
        //if (mProcessor == null) System.out.println("xxxxnull");
        //dont know why the processor was null in getExtendedPluginInfo()

        /* Commented block contains variables which are used only in the below commented block.
         *
         * Enumeration<String> mappers = mProcessor.getMapperInsts().keys();
        Enumeration<String> publishers = mProcessor.getPublisherInsts().keys();
        StringBuffer map = new StringBuffer();
        map.append(NOMAPPER);

        for (; mappers.hasMoreElements();) {
            String name = mappers.nextElement();

            map.append("," + name);
        }
        StringBuffer publish = new StringBuffer();

        for (; publishers.hasMoreElements();) {
            String name = publishers.nextElement();

            publish.append("," + name);
        }*/

        /*
         mExtendedPluginInfo = new NameValuePairs();
         mExtendedPluginInfo.add("type","choice(client,server,objSignClient,smime,ca,crl);The publishing object type");
         mExtendedPluginInfo.add("mapper","choice("+map+");Use the mapper to find the ldap dn \nto publish the certificate or crl");
         mExtendedPluginInfo.add("publisher","choice("+publish+");Use the publisher to publish the certificate or crl a directory etc");
         mExtendedPluginInfo.add("enable","boolean;");
         mExtendedPluginInfo.add("predicate","string;");
         */

        Vector<String> v = new Vector<>();

        try {
            v.addElement(PROP_TYPE + "=" + mConfig.getString(PROP_TYPE, ""));
            v.addElement(PROP_PREDICATE + "=" + mConfig.getString(PROP_PREDICATE, ""));
            v.addElement(PROP_ENABLE + "=" + mConfig.getString(PROP_ENABLE, ""));
            v.addElement(PROP_MAPPER + "=" + mConfig.getString(PROP_MAPPER, ""));
            v.addElement(PROP_PUBLISHER + "=" + mConfig.getString(PROP_PUBLISHER, ""));
        } catch (EBaseException e) {
        }
        return v;
    }

    /**
     * Sets a predicate expression for rule matching.
     * <P>
     *
     * @param exp The predicate expression for the rule.
     */
    public void setPredicate(LdapExpression exp) {
        mFilterExp = exp;
    }

    /**
     * Returns the predicate expression for the rule.
     * <P>
     *
     * @return The predicate expression for the rule.
     */
    public LdapExpression getPredicate() {
        return mFilterExp;
    }

    public String getMapper() {
        try {
            String map = mConfig.getString(PROP_MAPPER, "");

            if (map != null)
                map = map.trim();
            if (map == null || map.equals(""))
                return null;
            else if (map.equals(NOMAPPER))
                return null;
            else
                return map;
        } catch (EBaseException e) {
        }
        return null;
    }

    public String getPublisher() {
        try {
            return mConfig.getString(PROP_PUBLISHER, "");
        } catch (EBaseException e) {
        }
        return null;
    }

    public String getType() {
        try {
            return mConfig.getString(PROP_TYPE, "");
        } catch (EBaseException e) {
        }
        return null;
    }

    /**
     * Returns true if the rule is enabled, false if it's disabled.
     */
    public boolean enabled() {
        try {
            boolean enable = mConfig.getBoolean(PROP_ENABLE, false);

            //System.out.println(enable);
            return enable;
        } catch (EBaseException e) {
        }
        return false;
    }

    /**
     * Returns the initial default parameters.
     */
    public Vector<String> getDefaultParams() {
        Vector<String> v = new Vector<>();

        v.addElement(PROP_TYPE + "=");
        v.addElement(PROP_PREDICATE + "=");
        v.addElement(PROP_ENABLE + "=true");
        v.addElement(PROP_MAPPER + "=");
        v.addElement(PROP_PUBLISHER + "=");
        return v;
    }
}
