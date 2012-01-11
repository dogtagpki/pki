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
package com.netscape.certsrv.publish;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.security.x509.X509CRLImpl;

import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapConnModule;
import com.netscape.certsrv.request.IRequest;

/**
 * Controls the publishing process from the top level. Maintains
 * a collection of Publishers , Mappers, and Publish Rules.
 * 
 * @version $Revision$ $Date$
 */

public interface IPublisherProcessor extends ISubsystem {

    public final static String PROP_PUBLISH_SUBSTORE = "publish";
    public final static String PROP_LDAP_PUBLISH_SUBSTORE = "ldappublish";
    public final static String PROP_QUEUE_PUBLISH_SUBSTORE = "queue";

    public static final String PROP_LOCAL_CA = "cacert";
    public static final String PROP_LOCAL_CRL = "crl";
    public static final String PROP_CERTS = "certs";
    public static final String PROP_XCERT = "xcert";

    public static final String PROP_CLASS = "class";
    public static final String PROP_IMPL = "impl";
    public static final String PROP_PLUGIN = "pluginName";
    public static final String PROP_INSTANCE = "instance";

    public static final String PROP_PREDICATE = "predicate";
    public static final String PROP_ENABLE = "enable";
    public static final String PROP_LDAP = "ldap";
    public static final String PROP_MAPPER = "mapper";
    public static final String PROP_PUBLISHER = "publisher";
    public static final String PROP_TYPE = "type";

    /**
     * 
     * Returns Hashtable of rule plugins.
     */

    public Hashtable<String, RulePlugin> getRulePlugins();

    /**
     * 
     * Returns Hashtable of rule instances.
     */

    public Hashtable<String, ILdapRule> getRuleInsts();

    /**
     * 
     * Returns Hashtable of mapper plugins.
     */

    public Hashtable<String, MapperPlugin> getMapperPlugins();

    /**
     * 
     * Returns Hashtable of publisher plugins.
     */
    public Hashtable<String, PublisherPlugin> getPublisherPlugins();

    /**
     * 
     * Returns Hashtable of rule mapper instances.
     */
    public Hashtable<String, MapperProxy> getMapperInsts();

    /**
     * 
     * Returns Hashtable of rule publisher instances.
     */
    public Hashtable<String, PublisherProxy> getPublisherInsts();

    /**
     * 
     * Returns list of rules based on publishing type.
     * 
     * @param publishingType Type for which to retrieve rule list.
     */

    public Enumeration<ILdapRule> getRules(String publishingType);

    /**
     * 
     * Returns list of rules based on publishing type and publishing request.
     * 
     * @param publishingType Type for which to retrieve rule list.
     * @param req Corresponding publish request.
     */
    public Enumeration<ILdapRule> getRules(String publishingType, IRequest req);

    /**
     * 
     * Returns mapper initial default parameters.
     * 
     * @param implName name of MapperPlugin.
     */

    public Vector<String> getMapperDefaultParams(String implName) throws
            ELdapException;

    /**
     * 
     * Returns mapper current instance parameters.
     * 
     * @param insName name of MapperProxy.
     * @exception ELdapException failed due to Ldap error.
     */

    public Vector<String> getMapperInstanceParams(String insName) throws
            ELdapException;

    /**
     * 
     * Returns publisher initial default parameters.
     * 
     * @param implName name of PublisherPlugin.
     * @exception ELdapException failed due to Ldap error.
     */
    public Vector<String> getPublisherDefaultParams(String implName) throws
            ELdapException;

    /**
     * 
     * Returns true if MapperInstance is enabled.
     * 
     * @param insName name of MapperProxy.
     * @return true if enabled. false if disabled.
     */

    public boolean isMapperInstanceEnable(String insName);

    /**
     * 
     * Returns ILdapMapper instance that is currently active.
     * 
     * @param insName name of MapperProxy.
     * @return instance of ILdapMapper.
     */
    public ILdapMapper getActiveMapperInstance(String insName);

    /**
     * 
     * Returns ILdapMapper instance based on name of MapperProxy.
     * 
     * @param insName name of MapperProxy.
     * @return instance of ILdapMapper.
     */
    public ILdapMapper getMapperInstance(String insName);

    /**
     * 
     * Returns true publisher instance is currently enabled.
     * 
     * @param insName name of PublisherProxy.
     * @return true if enabled.
     */
    public boolean isPublisherInstanceEnable(String insName);

    /**
     * 
     * Returns ILdapPublisher instance that is currently active.
     * 
     * @param insName name of PublisherProxy.
     * @return instance of ILdapPublisher.
     */
    public ILdapPublisher getActivePublisherInstance(String insName);

    /**
     * 
     * Returns ILdapPublisher instance.
     * 
     * @param insName name of PublisherProxy.
     * @return instance of ILdapPublisher.
     */
    public ILdapPublisher getPublisherInstance(String insName);

    /**
     * 
     * Returns Vector of PublisherIntance's current instance parameters.
     * 
     * @param insName name of PublisherProxy.
     * @return Vector of current instance parameters.
     */
    public Vector<String> getPublisherInstanceParams(String insName) throws
            ELdapException;

    /**
     * 
     * Returns Vector of RulePlugin's initial default parameters.
     * 
     * @param implName name of RulePlugin.
     * @return Vector of initial default parameters.
     * @exception ELdapException failed due to Ldap error.
     */
    public Vector<String> getRuleDefaultParams(String implName) throws
            ELdapException;

    /**
     * 
     * Returns Vector of RulePlugin's current instance parameters.
     * 
     * @param implName name of RulePlugin.
     * @return Vector of current instance parameters.
     * @exception ELdapException failed due to Ldap error.
     */
    public Vector<String> getRuleInstanceParams(String implName) throws
            ELdapException;

    /**
     * Set published flag - true when published, false when unpublished.
     * Not exist means not published.
     * 
     * @param serialNo serial number of publishable object.
     * @param published true for published, false for not.
     */
    public void setPublishedFlag(BigInteger serialNo, boolean published);

    /**
     * Publish ca cert, UpdateDir.java, jobs, request listeners
     * 
     * @param cert X509 certificate to be published.
     * @exception ELdapException publish failed due to Ldap error.
     */
    public void publishCACert(X509Certificate cert)
            throws ELdapException;

    /**
     * This function is never called. CMS does not unpublish
     * CA certificate.
     */
    public void unpublishCACert(X509Certificate cert)
            throws ELdapException;

    /**
     * Publishs regular user certificate based on the criteria
     * set in the request.
     * 
     * @param cert X509 certificate to be published.
     * @param req request which provides the criteria
     * @exception ELdapException publish failed due to Ldap error.
     */
    public void publishCert(X509Certificate cert, IRequest req)
            throws ELdapException;

    /**
     * Unpublish user certificate. This is used by
     * UnpublishExpiredJob.
     * 
     * @param cert X509 certificate to be unpublished.
     * @param req request which provides the criteria
     * @exception ELdapException unpublish failed due to Ldap error.
     */
    public void unpublishCert(X509Certificate cert, IRequest req)
            throws ELdapException;

    /**
     * publishes a crl by mapping the issuer name in the crl to an entry
     * and publishing it there. entry must be a certificate authority.
     * Note that this is used by cmsgateway/cert/UpdateDir.java
     * 
     * @param crl Certificate Revocation List
     * @param crlIssuingPointId name of the issuing point.
     * @exception ELdapException publish failed due to Ldap error.
     */
    public void publishCRL(X509CRLImpl crl, String crlIssuingPointId)
            throws ELdapException;

    /**
     * publishes a crl by mapping the issuer name in the crl to an entry
     * and publishing it there. entry must be a certificate authority.
     * 
     * @param dn Distinguished name to publish.
     * @param crl Certificate Revocation List
     * @exception ELdapException publish failed due to Ldap error.
     */
    public void publishCRL(String dn, X509CRL crl)
            throws ELdapException;

    /**
     * 
     * Return true if Ldap is enabled.
     * 
     * @return true if Ldap is enabled,otherwise false.
     */

    public boolean ldapEnabled();

    /**
     * 
     * Return true of PublisherProcessor is enabled.
     * 
     * @return true if is enabled, otherwise false.
     * 
     */
    public boolean enabled();

    /**
     * 
     * Return Authority for which this Processor operates.
     * 
     * @return Authority.
     */

    public ISubsystem getAuthority();

    /**
     * 
     * Perform logging function for this Processor.
     * 
     * @param level Log level to be used for this message
     * @param msg Message to be logged.
     */

    public void log(int level, String msg);

    /**
     * 
     * Returns LdapConnModule belonging to this Processor.
     * 
     * @return LdapConnModule.
     */
    public ILdapConnModule getLdapConnModule();

    /**
     * Sets the LdapConnModule belonging to this Processor.
     * 
     * @param m ILdapConnModule.
     */
    public void setLdapConnModule(ILdapConnModule m);
}
