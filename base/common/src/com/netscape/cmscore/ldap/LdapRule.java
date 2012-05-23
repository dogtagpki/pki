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
import com.netscape.certsrv.publish.ILdapExpression;
import com.netscape.certsrv.publish.ILdapRule;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.cmscore.util.Debug;

/**
 * The publishing rule that links mapper and publisher together.
 */
public class LdapRule implements ILdapRule, IExtendedPluginInfo {
    public final static String NOMAPPER = "<NONE>";

    private IConfigStore mConfig = null;
    protected ILdapExpression mFilterExp = null;
    private String mInstanceName = null;

    private IPublisherProcessor mProcessor = null;

    private static String[] epi_params = null; // extendedpluginInfo

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    public String[] getExtendedPluginInfo(Locale locale) {
        //dont know why it's null here.
        //if (mProcessor == null) System.out.println("p null");

        if (Debug.ON) {
            Debug.trace("LdapRule: getExtendedPluginInfo() - returning epi_params:");
            for (int i = 0; i < epi_params.length; i++) {
                Debug.trace("[" + i + "]  " + epi_params[i]);
            }
        }
        return epi_params;
    }

    public void init(IPublisherProcessor processor, IConfigStore config) throws EBaseException {
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
        String exp = config.getString(IPublisherProcessor.PROP_PREDICATE, null);

        if (exp != null)
            exp = exp.trim();
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
        String exp = config.getString(IPublisherProcessor.PROP_PREDICATE, null);

        if (exp != null)
            exp = exp.trim();
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
     * Returns the description of the ldap publisher.
     */
    public String getDescription() {
        return "LdapRule";
    }

    /**
     * Set the instance name
     */
    public void setInstanceName(String insName) {
        mInstanceName = insName;
    }

    /**
     * Returns the instance name
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

        Vector<String> v = new Vector<String>();

        try {
            v.addElement(IPublisherProcessor.PROP_TYPE + "=" +
                    mConfig.getString(IPublisherProcessor.PROP_TYPE, ""));
            v.addElement(IPublisherProcessor.PROP_PREDICATE + "=" +
                    mConfig.getString(IPublisherProcessor.PROP_PREDICATE,
                            ""));
            v.addElement(IPublisherProcessor.PROP_ENABLE + "=" +
                    mConfig.getString(IPublisherProcessor.PROP_ENABLE,
                            ""));
            v.addElement(IPublisherProcessor.PROP_MAPPER + "=" +
                    mConfig.getString(IPublisherProcessor.PROP_MAPPER,
                            ""));
            v.addElement(IPublisherProcessor.PROP_PUBLISHER + "=" +
                    mConfig.getString(IPublisherProcessor.PROP_PUBLISHER,
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
            String map =
                    mConfig.getString(IPublisherProcessor.PROP_MAPPER, "");

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
            return mConfig.getString(IPublisherProcessor.PROP_PUBLISHER, "");
        } catch (EBaseException e) {
        }
        return null;
    }

    public String getType() {
        try {
            return mConfig.getString(IPublisherProcessor.PROP_TYPE, "");
        } catch (EBaseException e) {
        }
        return null;
    }

    public boolean enabled() {
        try {
            boolean enable =
                    mConfig.getBoolean(IPublisherProcessor.PROP_ENABLE, false);

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
        Vector<String> v = new Vector<String>();

        v.addElement(IPublisherProcessor.PROP_TYPE + "=");
        v.addElement(IPublisherProcessor.PROP_PREDICATE + "=");
        v.addElement(IPublisherProcessor.PROP_ENABLE + "=true");
        v.addElement(IPublisherProcessor.PROP_MAPPER + "=");
        v.addElement(IPublisherProcessor.PROP_PUBLISHER + "=");
        return v;
    }
}
