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
import java.util.Locale;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;

/**
 * The publishing rule which associates a Publisher with a Mapper.
 */
public class LdapRule implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LdapRule.class);

    public final static String PROP_PREDICATE = "predicate";
    public final static String PROP_ENABLE = "enable";
    public final static String PROP_IMPLNAME = "implName";

    public final static String NOMAPPER = "<NONE>";

    private IConfigStore mConfig = null;
    protected ILdapExpression mFilterExp = null;
    private String mInstanceName = null;

    private PublisherProcessor mProcessor;

    private static String[] epi_params = null; // extendedpluginInfo

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    @Override
    public String[] getExtendedPluginInfo(Locale locale) {
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
    public void init(PublisherProcessor processor, IConfigStore config) throws EBaseException {
        mConfig = config;

        mProcessor = processor;
        Enumeration<String> mappers = mProcessor.getMapperInsts().keys();
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
        String exp = config.getString(PublisherProcessor.PROP_PREDICATE, null);
        logger.info("LdapRule: predicate: " + exp);

        if (exp != null) {
            exp = exp.trim();
        }

        if (exp != null && exp.length() > 0) {
            ILdapExpression filterExp = LdapPredicateParser.parse(exp);
            setPredicate(filterExp);
        }

        //if (mProcessor == null) System.out.println("null");
    }

    /**
     * The init method in ILdapPlugin
     * It can not set set mapper,publisher choice for console dynamicly
     * Should not use this method to init.
     */
    public void init(IConfigStore config) throws EBaseException {
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
        String exp = config.getString(PublisherProcessor.PROP_PREDICATE, null);
        logger.info("LdapRule: predicate: " + exp);

        if (exp != null) {
            exp = exp.trim();
        }

        if (exp != null && exp.length() > 0) {
            ILdapExpression filterExp = LdapPredicateParser.parse(exp);
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
            v.addElement(PublisherProcessor.PROP_TYPE + "=" +
                    mConfig.getString(PublisherProcessor.PROP_TYPE, ""));
            v.addElement(PublisherProcessor.PROP_PREDICATE + "=" +
                    mConfig.getString(PublisherProcessor.PROP_PREDICATE,
                            ""));
            v.addElement(PublisherProcessor.PROP_ENABLE + "=" +
                    mConfig.getString(PublisherProcessor.PROP_ENABLE,
                            ""));
            v.addElement(PublisherProcessor.PROP_MAPPER + "=" +
                    mConfig.getString(PublisherProcessor.PROP_MAPPER,
                            ""));
            v.addElement(PublisherProcessor.PROP_PUBLISHER + "=" +
                    mConfig.getString(PublisherProcessor.PROP_PUBLISHER,
                            ""));
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
    public void setPredicate(ILdapExpression exp) {
        mFilterExp = exp;
    }

    /**
     * Returns the predicate expression for the rule.
     * <P>
     *
     * @return The predicate expression for the rule.
     */
    public ILdapExpression getPredicate() {
        return mFilterExp;
    }

    public String getMapper() {
        try {
            String map = mConfig.getString(PublisherProcessor.PROP_MAPPER, "");

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
            return mConfig.getString(PublisherProcessor.PROP_PUBLISHER, "");
        } catch (EBaseException e) {
        }
        return null;
    }

    public String getType() {
        try {
            return mConfig.getString(PublisherProcessor.PROP_TYPE, "");
        } catch (EBaseException e) {
        }
        return null;
    }

    /**
     * Returns true if the rule is enabled, false if it's disabled.
     */
    public boolean enabled() {
        try {
            boolean enable = mConfig.getBoolean(PublisherProcessor.PROP_ENABLE, false);

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

        v.addElement(PublisherProcessor.PROP_TYPE + "=");
        v.addElement(PublisherProcessor.PROP_PREDICATE + "=");
        v.addElement(PublisherProcessor.PROP_ENABLE + "=true");
        v.addElement(PublisherProcessor.PROP_MAPPER + "=");
        v.addElement(PublisherProcessor.PROP_PUBLISHER + "=");
        return v;
    }
}
