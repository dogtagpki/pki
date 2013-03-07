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
package com.netscape.cms.servlet.admin;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ExtendedPluginInfo;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.Plugin;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.ldap.ELdapException;
import com.netscape.certsrv.ldap.ILdapAuthInfo;
import com.netscape.certsrv.ldap.ILdapBoundConnFactory;
import com.netscape.certsrv.ldap.ILdapConnInfo;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.EMapperNotFound;
import com.netscape.certsrv.publish.EMapperPluginNotFound;
import com.netscape.certsrv.publish.EPublisherNotFound;
import com.netscape.certsrv.publish.EPublisherPluginNotFound;
import com.netscape.certsrv.publish.ERuleNotFound;
import com.netscape.certsrv.publish.ERulePluginNotFound;
import com.netscape.certsrv.publish.ILdapMapper;
import com.netscape.certsrv.publish.ILdapPublisher;
import com.netscape.certsrv.publish.ILdapRule;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.publish.MapperPlugin;
import com.netscape.certsrv.publish.MapperProxy;
import com.netscape.certsrv.publish.PublisherPlugin;
import com.netscape.certsrv.publish.PublisherProxy;
import com.netscape.certsrv.publish.RulePlugin;
import com.netscape.certsrv.security.ICryptoSubsystem;
import com.netscape.cmsutil.password.IPasswordStore;

/**
 * A class representing an publishing servlet for the
 * Publishing subsystem. This servlet is responsible
 * to serve configuration requests for the Publishing subsystem.
 *
 * @version $Revision$, $Date$
 */
public class PublisherAdminServlet extends AdminServlet {
    /**
     *
     */
    private static final long serialVersionUID = 7055088618787207262L;

    public final static String PROP_AUTHORITY = "authority";

    private final static String INFO = "PublisherAdminServlet";
    public final static String NOMAPPER = "<NONE>";
    private IPublisherProcessor mProcessor = null;
    private IAuthority mAuth = null;

    public PublisherAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String authority = config.getInitParameter(PROP_AUTHORITY);

        if (authority != null)
            mAuth = (IAuthority) CMS.getSubsystem(authority);
        if (mAuth != null)
            if (mAuth instanceof ICertificateAuthority) {
                mProcessor = ((ICertificateAuthority) mAuth).getPublisherProcessor();
            } else
                throw new ServletException(authority + "  does not have publishing processor!");
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP admin request.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);

        CMS.debug("PublisherAdminServlet: in service");
        String scope = req.getParameter(Constants.OP_SCOPE);
        String op = req.getParameter(Constants.OP_TYPE);

        if (op == null) {
            //System.out.println("SRVLT_INVALID_PROTOCOL");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_PROTOCOL"),
                    null, resp);
            return;
        }

        // for the rest
        try {
            super.authenticate(req);

            if (op.equals(OpDef.OP_AUTH)) { // for admin authentication only
                sendResponse(SUCCESS, null, null, resp);
                return;
            }
        } catch (IOException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }
        try {
            AUTHZ_RES_NAME = "certServer.publisher.configuration";
            if (scope != null) {
                if (op.equals(OpDef.OP_READ)) {
                    mOp = "read";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_LDAP)) {
                        getLDAPDest(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_PUBLISHER_IMPLS)) {
                        getConfig(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_PUBLISHER_RULES)) {
                        getInstConfig(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_IMPLS)) {
                        getMapperConfig(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_RULES)) {
                        getMapperInstConfig(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_IMPLS)) {
                        getRuleConfig(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_EXTENDED_PLUGIN_INFO)) {
                        getExtendedPluginInfo(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_RULES)) {
                        getRuleInstConfig(req, resp);
                        return;
                    }
                } else if (op.equals(OpDef.OP_MODIFY)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_LDAP)) {
                        setLDAPDest(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_PUBLISHER_RULES)) {
                        modPublisherInst(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_RULES)) {
                        modMapperInst(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_RULES)) {
                        modRuleInst(req, resp, scope);
                        return;
                    }
                } else if (op.equals(OpDef.OP_PROCESS)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_LDAP)) {
                        testSetLDAPDest(req, resp);
                        return;
                    }
                } else if (op.equals(OpDef.OP_SEARCH)) {
                    mOp = "read";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_PUBLISHER_IMPLS)) {
                        listPublisherPlugins(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_PUBLISHER_RULES)) {
                        listPublisherInsts(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_IMPLS)) {
                        listMapperPlugins(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_RULES)) {
                        listMapperInsts(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_IMPLS)) {
                        listRulePlugins(req, resp);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_RULES)) {
                        listRuleInsts(req, resp);
                        return;
                    }
                } else if (op.equals(OpDef.OP_ADD)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_PUBLISHER_IMPLS)) {
                        addPublisherPlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_PUBLISHER_RULES)) {
                        addPublisherInst(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_IMPLS)) {
                        addMapperPlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_RULES)) {
                        addMapperInst(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_IMPLS)) {
                        addRulePlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_RULES)) {
                        addRuleInst(req, resp, scope);
                        return;
                    }
                } else if (op.equals(OpDef.OP_DELETE)) {
                    mOp = "modify";
                    if ((mToken = super.authorize(req)) == null) {
                        sendResponse(ERROR,
                                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                                null, resp);
                        return;
                    }
                    if (scope.equals(ScopeDef.SC_PUBLISHER_IMPLS)) {
                        delPublisherPlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_PUBLISHER_RULES)) {
                        delPublisherInst(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_IMPLS)) {
                        delMapperPlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_MAPPER_RULES)) {
                        delMapperInst(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_IMPLS)) {
                        delRulePlugin(req, resp, scope);
                        return;
                    } else if (scope.equals(ScopeDef.SC_RULE_RULES)) {
                        delRuleInst(req, resp, scope);
                        return;
                    }
                } else {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_TYPE", op),
                            null, resp);
                    return;
                }
            } else {
                //System.out.println("SRVLT_INVALID_OP_SCOPE");
                sendResponse(ERROR,
                        CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_INVALID_OP_SCOPE"),
                        null, resp);
                return;
            }
        } catch (EBaseException e) {
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        }
        //System.out.println("SRVLT_FAIL_PERFORM 2");
        sendResponse(ERROR,
                CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_PERFORM_FAILED"),
                null, resp);
        return;
    }

    private IExtendedPluginInfo getExtendedPluginInfo(IPublisherProcessor
            p) {
        Enumeration<String> mappers = p.getMapperInsts().keys();
        Enumeration<String> publishers = p.getPublisherInsts().keys();

        StringBuffer map = new StringBuffer();

        for (; mappers.hasMoreElements();) {
            String name = mappers.nextElement();

            if (map.length() == 0) {
                map.append(name);
            } else {
                map.append(",");
                map.append(name);
            }
        }
        StringBuffer publish = new StringBuffer();

        for (; publishers.hasMoreElements();) {
            String name = publishers.nextElement();

            publish.append(",");
            publish.append(name);
        }

        String epi[] = new String[] {
                "type;choice(cacert,crl,certs,xcert);The certType of the request",
                "mapper;choice("
                        + map.toString()
                        + ");Use the mapper to find the ldap dn to publish the certificate or crl",
                "publisher;choice("
                        + publish.toString()
                        + ");Use the publisher to publish the certificate or crl a directory etc",
                "enable;boolean;",
                "predicate;string;"
        };

        return new ExtendedPluginInfo(epi);
    }

    private NameValuePairs getExtendedPluginInfo(Locale locale, String implType, String implName) {
        IExtendedPluginInfo ext_info = null;
        Object impl = null;

        if (implType.equals(Constants.PR_EXT_PLUGIN_IMPLTYPE_PUBLISHRULE)) {
            IPublisherProcessor p_processor = mProcessor;

            // Should get the registered rules from processor
            // instead of plugin
            // OLD: impl = getClassByNameAsExtendedPluginInfo(plugin.getClassPath());
            impl = getExtendedPluginInfo(p_processor);
        } else if (implType.equals(Constants.PR_EXT_PLUGIN_IMPLTYPE_MAPPER)) {
            IPublisherProcessor p_processor = mProcessor;
            Plugin plugin = p_processor.getMapperPlugins().get(implName
                    );

            impl = getClassByNameAsExtendedPluginInfo(plugin.getClassPath());

        } else if (implType.equals(Constants.PR_EXT_PLUGIN_IMPLTYPE_PUBLISHER)) {
            IPublisherProcessor p_processor = mProcessor;
            Plugin plugin = p_processor.getPublisherPlugins().get(implName);

            impl = getClassByNameAsExtendedPluginInfo(plugin.getClassPath());
        }
        if (impl != null) {
            if (impl instanceof IExtendedPluginInfo) {
                ext_info = (IExtendedPluginInfo) impl;
            }
        }

        NameValuePairs nvps = null;

        if (ext_info == null) {
            nvps = new NameValuePairs();
        } else {
            nvps = convertStringArrayToNVPairs(ext_info.getExtendedPluginInfo(locale));
        }

        return nvps;

    }

    /**
     * retrieve extended plugin info such as brief description, type info
     * from policy, authentication,
     * need to add: listener, mapper and publishing plugins
     */
    private void getExtendedPluginInfo(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        int colon = id.indexOf(':');

        String implType = id.substring(0, colon);
        String implName = id.substring(colon + 1);

        NameValuePairs params =
                getExtendedPluginInfo(getLocale(req), implType, implName);

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getLDAPDest(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        IConfigStore config = mAuth.getConfigStore();
        IConfigStore publishcfg = config.getSubStore(IPublisherProcessor.PROP_PUBLISH_SUBSTORE);
        IConfigStore ldapcfg = publishcfg.getSubStore(IPublisherProcessor.PROP_LDAP_PUBLISH_SUBSTORE);
        IConfigStore ldap = ldapcfg.getSubStore(IPublisherProcessor.PROP_LDAP);

        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_ENABLE))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_ENABLE))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_THREADS))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_PRIORITY))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_STATUS))
                continue;
            if (name.equals(Constants.PR_CERT_NAMES)) {
                ICryptoSubsystem jss = (ICryptoSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

                params.put(name, jss.getAllCerts());
            } else {
                String value = ldap.getString(name, "");

                if (value == null || value.equals("")) {
                    if (name.equals(ILdapBoundConnFactory.PROP_LDAPCONNINFO + "." + ILdapConnInfo.PROP_HOST)) {
                        value = mConfig.getString(ConfigConstants.PR_MACHINE_NAME, null);
                    } else if (name.equals(ILdapBoundConnFactory.PROP_LDAPCONNINFO + "." + ILdapConnInfo.PROP_PORT)) {
                        value = ILdapConnInfo.PROP_PORT_DEFAULT;
                    } else if (name.equals(ILdapBoundConnFactory.PROP_LDAPAUTHINFO + "." + ILdapAuthInfo.PROP_BINDDN)) {
                        value = ILdapAuthInfo.PROP_BINDDN_DEFAULT;
                    }
                }
                params.put(name, value);
            }
        }
        params.put(Constants.PR_PUBLISHING_ENABLE,
                publishcfg.getString(IPublisherProcessor.PROP_ENABLE, Constants.FALSE));
        params.put(Constants.PR_PUBLISHING_QUEUE_ENABLE,
                publishcfg.getString(Constants.PR_PUBLISHING_QUEUE_ENABLE, Constants.TRUE));
        params.put(Constants.PR_PUBLISHING_QUEUE_THREADS,
                publishcfg.getString(Constants.PR_PUBLISHING_QUEUE_THREADS, "3"));
        params.put(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE,
                publishcfg.getString(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE, "40"));
        params.put(Constants.PR_PUBLISHING_QUEUE_PRIORITY,
                publishcfg.getString(Constants.PR_PUBLISHING_QUEUE_PRIORITY, "0"));
        params.put(Constants.PR_PUBLISHING_QUEUE_STATUS,
                publishcfg.getString(Constants.PR_PUBLISHING_QUEUE_STATUS, "200"));
        params.put(Constants.PR_ENABLE,
                ldapcfg.getString(IPublisherProcessor.PROP_ENABLE, Constants.FALSE));
        sendResponse(SUCCESS, null, params, resp);
    }

    private void setLDAPDest(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {

        //Save New Settings to the config file
        IConfigStore config = mAuth.getConfigStore();
        IConfigStore publishcfg = config.getSubStore(IPublisherProcessor.PROP_PUBLISH_SUBSTORE);
        IConfigStore ldapcfg = publishcfg.getSubStore(IPublisherProcessor.PROP_LDAP_PUBLISH_SUBSTORE);
        IConfigStore ldap = ldapcfg.getSubStore(IPublisherProcessor.PROP_LDAP);

        //set enable flag
        publishcfg.putString(IPublisherProcessor.PROP_ENABLE, req.getParameter(Constants.PR_PUBLISHING_ENABLE));
        String enable = req.getParameter(Constants.PR_ENABLE);

        ldapcfg.putString(IPublisherProcessor.PROP_ENABLE, enable);
        if (enable.equals("false")) {
            // need to disable the ldap module here
            mProcessor.setLdapConnModule(null);
        }

        //set reset of the parameters
        Enumeration<String> e = req.getParameterNames();
        String pwd = null;

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_ENABLE))
                continue;
            // don't store password in the config file.
            if (name.equals(Constants.PR_BIND_PASSWD))
                continue; // old style password read from config.
            if (name.equals(Constants.PR_DIRECTORY_MANAGER_PWD)) {
                pwd = req.getParameter(name);
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_ENABLE)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_THREADS)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_PRIORITY)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_STATUS)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }

            /* Don't enter the publishing pw into the config store */
            ldap.putString(name, req.getParameter(name));
        }

        commit(true);

        /* Do a "PUT" of the new pw to the watchdog"
         ** do not remove - cfu
        if (pwd != null)
            CMS.putPasswordCache(PW_TAG_CA_LDAP_PUBLISHING, pwd);
         */

        // support publishing dirsrv with different pwd than internaldb
        // update passwordFile
        String prompt = ldap.getString(Constants.PR_BINDPWD_PROMPT);
        IPasswordStore pwdStore = CMS.getPasswordStore();
        CMS.debug("PublisherAdminServlet: setLDAPDest(): saving password for " + prompt + " to password file");
        pwdStore.putPassword(prompt, pwd);
        pwdStore.commit();
        CMS.debug("PublisherAdminServlet: setLDAPDest(): password saved");

        /* we'll shut down and restart the PublisherProcessor instead
                // what a hack to  do this without require restart server
        //        ILdapAuthInfo authInfo = CMS.getLdapAuthInfo();
                ILdapConnModule connModule = mProcessor.getLdapConnModule();
                ILdapAuthInfo authInfo = null;
                if (connModule != null) {
                    authInfo = connModule.getLdapAuthInfo();
                }

        //        authInfo.addPassword(PW_TAG_CA_LDAP_PUBLISHING, pwd);
                if (authInfo != null) {
                    CMS.debug("PublisherAdminServlet: setLDAPDest(): adding password to memory cache");
                    authInfo.addPassword(prompt, pwd);
                } else
                    CMS.debug("PublisherAdminServlet: setLDAPDest(): authInfo null");
        */

        try {
            CMS.debug("PublisherAdminServlet: setLDAPDest(): restarting publishing processor");
            mProcessor.shutdown();
            mProcessor.startup();
            CMS.debug("PublisherAdminServlet: setLDAPDest(): publishing processor restarted");
        } catch (Exception ex) {
            // force to save the config even there is error
            // ignore any exception
            log(ILogger.LL_FAILURE, CMS.getLogMessage("ADMIN_SRVLT_FAIL_RES_LDAP", ex.toString()));
        }

        //XXX See if we can dynamically in B2
        sendResponse(SUCCESS, null, null, resp);
    }

    private void testSetLDAPDest(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        CMS.debug("PublisherAdmineServlet: in testSetLDAPDest");
        //Save New Settings to the config file
        IConfigStore config = mAuth.getConfigStore();
        IConfigStore publishcfg = config.getSubStore(IPublisherProcessor.PROP_PUBLISH_SUBSTORE);
        IConfigStore ldapcfg = publishcfg.getSubStore(IPublisherProcessor.PROP_LDAP_PUBLISH_SUBSTORE);
        IConfigStore ldap = ldapcfg.getSubStore(IPublisherProcessor.PROP_LDAP);

        //set enable flag
        publishcfg.putString(IPublisherProcessor.PROP_ENABLE,
                req.getParameter(Constants.PR_PUBLISHING_ENABLE));
        String ldapPublish = req.getParameter(Constants.PR_ENABLE);

        ldapcfg.putString(IPublisherProcessor.PROP_ENABLE, ldapPublish);
        if (ldapPublish.equals("false")) {
            // need to disable the ldap module here
            mProcessor.setLdapConnModule(null);
        }

        //set reset of the parameters
        Enumeration<String> e = req.getParameterNames();
        String pwd = null;

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_ENABLE))
                continue;
            if (name.equals(Constants.PR_PUBLISHING_ENABLE))
                continue;
            // don't store password in the config file.
            if (name.equals(Constants.PR_BIND_PASSWD))
                continue; // old style password read from config.
            if (name.equals(Constants.PR_DIRECTORY_MANAGER_PWD)) {
                pwd = req.getParameter(name);
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_ENABLE)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_THREADS)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_PAGE_SIZE)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_PRIORITY)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }
            if (name.equals(Constants.PR_PUBLISHING_QUEUE_STATUS)) {
                publishcfg.putString(name, req.getParameter(name));
                continue;
            }

            /* Don't enter the publishing pw into the config store */
            ldap.putString(name, req.getParameter(name));
        }

        // test before commit
        if (publishcfg.getBoolean(IPublisherProcessor.PROP_ENABLE) &&
                ldapcfg.getBoolean(IPublisherProcessor.PROP_ENABLE)) {
            params.put("title",
                    "You've attempted to configure CMS to connect" +
                            " to a LDAP directory. The connection status is" +
                            " as follows:\n \n");
            LDAPConnection conn = null;
            ILdapConnInfo connInfo =
                    CMS.getLdapConnInfo(ldap.getSubStore(
                            ILdapBoundConnFactory.PROP_LDAPCONNINFO));
            //LdapAuthInfo authInfo =
            //new LdapAuthInfo(ldap.getSubStore(
            //			   ILdapBoundConnFactory.PROP_LDAPAUTHINFO));
            String host = connInfo.getHost();
            int port = connInfo.getPort();
            boolean secure = connInfo.getSecure();
            //int authType = authInfo.getAuthType();
            String authType = ldap.getSubStore(
                    ILdapBoundConnFactory.PROP_LDAPAUTHINFO).getString(ILdapAuthInfo.PROP_LDAPAUTHTYPE);
            int version = connInfo.getVersion();
            String bindAs = null;
            String certNickName = null;

            if (authType.equals(ILdapAuthInfo.LDAP_SSLCLIENTAUTH_STR)) {
                try {
                    //certNickName = authInfo.getParms()[0];
                    certNickName =
                            ldap.getSubStore(
                                    ILdapBoundConnFactory.PROP_LDAPAUTHINFO).getString(
                                    ILdapAuthInfo.PROP_CLIENTCERTNICKNAME);
                    conn = new LDAPConnection(CMS.getLdapJssSSLSocketFactory(
                                    certNickName));
                    CMS.debug("Publishing Test certNickName=" + certNickName);
                    params.put(Constants.PR_CONN_INITED,
                            "Create ssl LDAPConnection with certificate: " +
                                    certNickName + dashes(70 - 44 - certNickName.length()) + " Success");
                } catch (Exception ex) {
                    params.put(Constants.PR_CONN_INIT_FAIL,
                            "Create ssl LDAPConnection with certificate: "
                                    +
                                    certNickName + dashes(70 - 44 - certNickName.length()) + " failure\n"
                                    + " exception: " + ex);
                    params.put(Constants.PR_SAVE_NOT,
                            "\n \nIf the problem is not fixed then LDAP publishing will fail.\n" +
                                    "Do you want to save the configuration anyway?");
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                }
                try {
                    conn.connect(host, port);
                    params.put(Constants.PR_CONN_OK,
                            "Connect to directory server "
                                    +
                                    host + " at port " + port +
                                    dashes(70 - 37 - host.length() - (Integer.valueOf(port)).toString().length())
                                    + " Success");
                    params.put(Constants.PR_AUTH_OK,
                            "Authentication: SSL client authentication" +
                                    dashes(70 - 41) + " Success" +
                                    "\nBind to the directory as: " + certNickName +
                                    dashes(70 - 26 - certNickName.length()) + " Success");
                } catch (LDAPException ex) {
                    if (ex.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                        // need to intercept this because message from LDAP is
                        // "DSA is unavailable" which confuses with DSA PKI.
                        params.put(Constants.PR_CONN_FAIL,
                                "Connect to directory server " +
                                        host + " at port " + port +
                                        dashes(70 - 37 - host.length() - (Integer.valueOf(port)).toString().length()) +
                                        " Failure\n" +
                                        " error: server unavailable");
                    } else {
                        params.put(Constants.PR_CONN_FAIL,
                                "Connect to directory server " +
                                        host + " at port " + port +
                                        dashes(70 - 37 - host.length() - (Integer.valueOf(port)).toString().length()) +
                                        " Failure");
                    }
                    params.put(Constants.PR_SAVE_NOT,
                            "\n \nIf the problem is not fixed then " +
                                    "LDAP publishing will fail.\n" +
                                    "Do you want to save the configuration anyway?");
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                }
            } else {
                try {
                    if (secure) {
                        conn = new LDAPConnection(
                                    CMS.getLdapJssSSLSocketFactory());
                        params.put(Constants.PR_CONN_INITED,
                                "Create ssl LDAPConnection" +
                                        dashes(70 - 25) + " Success");
                    } else {
                        conn = new LDAPConnection();
                        params.put(Constants.PR_CONN_INITED,
                                "Create LDAPConnection" +
                                        dashes(70 - 21) + " Success");
                    }
                } catch (Exception ex) {
                    params.put(Constants.PR_CONN_INIT_FAIL,
                            "Create LDAPConnection" +
                                    dashes(70 - 21) + " Failure\n" +
                                    "exception: " + ex);
                    params.put(Constants.PR_SAVE_NOT,
                            "\n \nIf the problem is not fixed then " +
                                    "LDAP publishing will fail.\n" +
                                    "Do you want to save the configuration anyway?");
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                }
                try {
                    conn.connect(host, port);
                    params.put(Constants.PR_CONN_OK,
                            "Connect to directory server "
                                    +
                                    host + " at port " + port +
                                    dashes(70 - 37 - host.length() - (Integer.valueOf(port)).toString().length())
                                    + " Success");
                } catch (LDAPException ex) {
                    if (ex.getLDAPResultCode() == LDAPException.UNAVAILABLE) {
                        // need to intercept this because message from LDAP is
                        // "DSA is unavailable" which confuses with DSA PKI.
                        params.put(Constants.PR_CONN_FAIL,
                                "Connect to directory server "
                                        +
                                        host + " at port " + port +
                                        dashes(70 - 37 - host.length() - (Integer.valueOf(port)).toString().length())
                                        + " Failure" +
                                        "\nerror: server unavailable");
                    } else {
                        params.put(Constants.PR_CONN_FAIL,
                                "Connect to directory server "
                                        +
                                        host + " at port " + port +
                                        dashes(70 - 37 - host.length() - (Integer.valueOf(port)).toString().length())
                                        + " Failure" +
                                        "\nexception: " + ex);
                    }
                    params.put(Constants.PR_SAVE_NOT,
                            "\n \nIf the problem is not fixed then " +
                                    "LDAP publishing will fail.\n" +
                                    "Do you want to save the configuration anyway?");
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                }
                try {
                    //bindAs = authInfo.getParms()[0];
                    bindAs = ldap.getSubStore(
                                ILdapBoundConnFactory.PROP_LDAPAUTHINFO).getString(ILdapAuthInfo.PROP_BINDDN);
                    conn.authenticate(version, bindAs, pwd);
                    params.put(Constants.PR_AUTH_OK,
                            "Authentication: Basic authentication" +
                                    dashes(70 - 36) + " Success" +
                                    "\nBind to the directory as: " + bindAs +
                                    dashes(70 - 26 - bindAs.length()) + " Success");
                } catch (LDAPException ex) {
                    if (ex.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                        params.put(Constants.PR_AUTH_FAIL,
                                "Authentication: Basic authentication" +
                                        dashes(70 - 36) + "Failure" +
                                        "\nBind to the directory as: " + bindAs +
                                        dashes(70 - 26 - bindAs.length()) +
                                        "Failure" + "\nThe object doesn't exist. " +
                                        "Please correct the value assigned in the" +
                                        " \"Directory manager DN\" field.");
                    } else if (ex.getLDAPResultCode() == LDAPException.INVALID_CREDENTIALS) {
                        params.put(Constants.PR_AUTH_FAIL,
                                "Authentication: Basic authentication" +
                                        dashes(70 - 36) + " Failure" +
                                        "\nBind to the directory as: " + bindAs +
                                        dashes(70 - 26 - bindAs.length()) +
                                        " Failure" + "\nInvalid password. " +
                                        "Please correct the value assigned in the" +
                                        " \"Password\" field.");
                    } else {
                        params.put(Constants.PR_AUTH_FAIL,
                                "Authentication: Basic authentication" +
                                        dashes(70 - 36) + " Failure" +
                                        "\nBind to the directory as: " + bindAs +
                                        dashes(70 - 26 - bindAs.length()) +
                                        " Failure");
                    }
                    params.put(Constants.PR_SAVE_NOT,
                            "\n \nIf the problem is not fixed then " +
                                    "LDAP publishing will fail.\n" +
                                    "Do you want to save the configuration anyway?");
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                }
            }

        }

        //commit(true);
        if (ldapcfg.getBoolean(IPublisherProcessor.PROP_ENABLE) &&
                pwd != null) {

            /* Do a "PUT" of the new pw to the watchdog"
             ** do not remove - cfu
            CMS.putPasswordCache(PW_TAG_CA_LDAP_PUBLISHING, pwd);
             */

            // support publishing dirsrv with different pwd than internaldb
            // update passwordFile
            String prompt = ldap.getString(Constants.PR_BINDPWD_PROMPT);
            IPasswordStore pwdStore = CMS.getPasswordStore();
            CMS.debug("PublisherAdminServlet: testSetLDAPDest(): saving password for " +
                    prompt + " to password file");
            pwdStore.putPassword(prompt, pwd);
            pwdStore.commit();
            CMS.debug("PublisherAdminServlet: testSetLDAPDest(): password saved");
            /* we'll shut down and restart the PublisherProcessor instead
                         // what a hack to  do this without require restart server
            //        ILdapAuthInfo authInfo = CMS.getLdapAuthInfo();
                        ILdapConnModule connModule = mProcessor.getLdapConnModule();
                        ILdapAuthInfo authInfo = null;
                        if (connModule != null) {
                            authInfo = connModule.getLdapAuthInfo();
                        } else
                            CMS.debug("PublisherAdminServlet: testSetLDAPDest(): connModule null");

            //        authInfo.addPassword(PW_TAG_CA_LDAP_PUBLISHING, pwd);
                        if (authInfo != null) {
                            CMS.debug("PublisherAdminServlet: testSetLDAPDest(): adding password to memory cache");
                            authInfo.addPassword(prompt, pwd);
                        } else
                            CMS.debug("PublisherAdminServlet: testSetLDAPDest(): authInfo null");
            */
        }
        //params.add(Constants.PR_SAVE_OK,
        //		   "\n \nConfiguration changes are now committed.");

        mProcessor.shutdown();

        if (publishcfg.getBoolean(IPublisherProcessor.PROP_ENABLE)) {
            mProcessor.startup();
            //params.add("restarted", "Publishing is restarted.");

            if (ldapcfg.getBoolean(IPublisherProcessor.PROP_ENABLE)) {
                ICertAuthority authority = (ICertAuthority) mProcessor.getAuthority();

                if (!(authority instanceof ICertificateAuthority))
                    return;
                ICertificateAuthority ca = (ICertificateAuthority) authority;

                // publish ca cert
                try {
                    mProcessor.publishCACert(ca.getCACert());
                    CMS.debug("PublisherAdminServlet: " + CMS.getLogMessage("ADMIN_SRVLT_PUB_CA_CERT"));
                    params.put("publishCA",
                            "CA certificate is published.");
                } catch (Exception ex) {
                    // exception not thrown - not seen as a fatal error.
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("ADMIN_SRVLT_NO_PUB_CA_CERT", ex.toString()));
                    params.put("publishCA",
                            "Failed to publish CA certificate.");
                    int index = ex.toString().indexOf("Failed to create CA");

                    if (index > -1) {
                        params.put("createError",
                                ex.toString().substring(index));
                    }
                    mProcessor.shutdown();
                    // Do you want to enable LDAP publishing anyway
                    params.put(Constants.PR_SAVE_NOT,
                            "\n \nIf the problem is not fixed then " +
                                    "the CA certificate won't be published.\n" +
                                    "Do you want to enable LDAP publishing anyway?");
                    sendResponse(SUCCESS, null, params, resp);
                    return;

                }
                // publish crl
                try {
                    CMS.debug("PublisherAdminServlet: about to update CRL");
                    ca.publishCRLNow();
                    CMS.debug(CMS.getLogMessage("ADMIN_SRVLT_PUB_CRL"));
                    params.put("publishCRL",
                            "CRL is published.");
                } catch (Exception ex) {
                    // exception not thrown - not seen as a fatal error.
                    log(ILogger.LL_FAILURE,
                            "Could not publish crl " + ex.toString());
                    params.put("publishCRL",
                            "Failed to publish CRL.");
                    mProcessor.shutdown();
                    // Do you want to enable LDAP publishing anyway
                    params.put(Constants.PR_SAVE_NOT,
                            "\n \nIf the problem is not fixed then " +
                                    "the CRL won't be published.\n" +
                                    "Do you want to enable LDAP publishing anyway?");
                    sendResponse(SUCCESS, null, params, resp);
                    return;
                }
            }
            commit(true);
            params.put(Constants.PR_SAVE_OK,
                    "\n \nConfiguration changes are now committed.");
            params.put("restarted", "Publishing is restarted.");
        } else {
            commit(true);
            params.put(Constants.PR_SAVE_OK,
                    "\n \nConfiguration changes are now committed.");
            params.put("stopped",
                    "Publishing is stopped.");
        }

        //XXX See if we can dynamically in B2
        sendResponse(SUCCESS, null, params, resp);
    }

    private synchronized void addMapperPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // is the manager id unique?
        if (mProcessor.getMapperPlugins().containsKey(id)) {
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_PLUGIN_ID", id))
                            .toString(),
                    null, resp);
            return;
        }

        String classPath = req.getParameter(Constants.PR_MAPPER_CLASS);

        if (classPath == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NULL_CLASS"), null, resp);
            return;
        }

        IConfigStore destStore = null;

        destStore = mConfig.getSubStore(mAuth.getId() + ".publish.mapper");
        IConfigStore instancesConfig = destStore.getSubStore("impl");

        // Does the class exist?
        Class<?> newImpl = null;

        try {
            newImpl = Class.forName(classPath);
        } catch (ClassNotFoundException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NO_CLASS"), null, resp);
            return;
        } catch (IllegalArgumentException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NO_CLASS"), null, resp);
            return;
        }

        // is the class an ILdapMapper?
        try {
            if (ILdapMapper.class.isAssignableFrom(newImpl) == false) {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_CLASS", classPath), null,
                        resp);
                return;
            }
        } catch (NullPointerException e) { // unlikely, only if newImpl null.
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_CLASS", classPath), null, resp);
            return;
        }

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put(Constants.PR_MAPPER_CLASS, classPath);

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // add mapper to registry.
        MapperPlugin plugin = new MapperPlugin(id, classPath);

        mProcessor.getMapperPlugins().put(id, plugin);
        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_MAPPER_ADDED", ""));

        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private boolean isValidID(String id) {
        if (id == null)
            return false;
        for (int i = 0; i < id.length(); i++) {
            if (!Character.isLetterOrDigit(id.charAt(i)))
                return false;
        }
        return true;
    }

    private synchronized void addMapperInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        if (!isValidID(id)) {
            sendResponse(ERROR, "Invalid ID '" + id + "'",
                    null, resp);
            return;
        }

        if (mProcessor.getMapperInsts().containsKey(id)) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_INST_ID", id),
                    null, resp);
            return;
        }

        // get required parameters
        String implname = req.getParameter(
                Constants.PR_MAPPER_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ADD_MISSING_PARAMS"), null, resp);
            return;
        }

        // check if implementation exists.
        MapperPlugin plugin =
                mProcessor.getMapperPlugins().get(
                implname);

        if (plugin == null) {
            sendResponse(
                    ERROR,
                    new EMapperPluginNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_MAPPER_PLUGIN_NOT_FOUND",
                            implname)).toString(),
                    null, resp);
            return;
        }

        Vector<String> configParams = mProcessor.getMapperDefaultParams(implname);

        IConfigStore destStore = mConfig.getSubStore(mAuth.getId() + ".publish.mapper");
        IConfigStore instancesConfig = destStore.getSubStore("instance");
        IConfigStore substore = instancesConfig.makeSubStore(id);

        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');
                String val = req.getParameter(kv.substring(0, index));

                if (val == null) {
                    substore.put(kv.substring(0, index),
                            kv.substring(index + 1));
                } else {
                    substore.put(kv.substring(0, index),
                            val);
                }
            }
        }
        substore.put("pluginName", implname);

        // Instantiate an object for this implementation
        String className = plugin.getClassPath();
        ILdapMapper mapperInst = null;

        try {
            mapperInst = (ILdapMapper) Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        }

        // initialize the mapper
        try {
            mapperInst.init(substore);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        } catch (Throwable e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR, e.toString(), null, resp);
            return;
        }

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            // clean up.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // inited and commited ok. now add mapper instance to list.
        mProcessor.getMapperInsts().put(id, new MapperProxy(true, mapperInst));

        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_MAPPER_INST_ADDED", id));

        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_MAPPER_IMPL_NAME, implname);
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void listMapperPlugins(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mProcessor.getMapperPlugins().keys();

        while (e.hasMoreElements()) {
            String name = e.nextElement();
            MapperPlugin value = mProcessor.getMapperPlugins().get(name);
            // get Description
            String c = value.getClassPath();
            String desc = "unknown";

            try {
                ILdapMapper lp = (ILdapMapper)
                        Class.forName(c).newInstance();

                desc = lp.getDescription();
            } catch (Exception exp) {
                sendResponse(ERROR, exp.toString(), null,
                        resp);
                return;
            }
            params.put(name, value.getClassPath() + "," + desc);
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    public String getMapperPluginName(ILdapMapper mapper) {
        IConfigStore cs = mapper.getConfigStore();

        try {
            return cs.getString("pluginName", "");
        } catch (EBaseException e) {
            return "";
        }
    }

    private synchronized void listMapperInsts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mProcessor.getMapperInsts().keys();

        for (; e.hasMoreElements();) {
            String name = e.nextElement();
            ILdapMapper value = mProcessor.getMapperInstance(name);

            params.put(name, getMapperPluginName(value) + ";visible");
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void delMapperInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does a`mapper instance exist?
        if (mProcessor.getMapperInsts().containsKey(id) == false) {
            sendResponse(
                    ERROR,
                    new EMapperNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_MAPPER_NOT_FOUND", id)).toString(),
                    null, resp);
            return;
        }

        // only remove from memory
        // cannot shutdown because we don't keep track of whether it's
        // being used.
        mProcessor.getMapperInsts().remove(id);

        // remove the configuration.
        IConfigStore destStore =
                mConfig.getSubStore(
                        mAuth.getId() + ".publish.mapper");
        IConfigStore instancesConfig = destStore.getSubStore("instance");

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void delMapperPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        if (mProcessor.getMapperPlugins().containsKey(id) == false) {
            sendResponse(
                    ERROR,
                    new EMapperPluginNotFound(CMS
                            .getUserMessage(getLocale(req), "CMS_LDAP_MAPPER_PLUGIN_NOT_FOUND", id)).toString(),
                    null, resp);
            return;
        }

        // first check if any instances from this mapper
        // DON'T remove mapper if any instance
        for (Enumeration<String> e = mProcessor.getMapperInsts().keys(); e.hasMoreElements();) {
            String name = e.nextElement();
            ILdapMapper mapper = mProcessor.getMapperInstance(name);

            if (id.equals(getMapperPluginName(mapper))) {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_IN_USE"), null, resp);
                return;
            }
        }

        // then delete this mapper
        mProcessor.getMapperPlugins().remove(id);

        IConfigStore destStore =
                mConfig.getSubStore(
                        mAuth.getId() + ".publish.mapper");
        IConfigStore instancesConfig =
                destStore.getSubStore("impl");

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void getMapperConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {

        String implname = req.getParameter(Constants.RS_ID);

        if (implname == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        Vector<String> configParams = mProcessor.getMapperDefaultParams(implname);
        NameValuePairs params = new NameValuePairs();

        // implName is always required so always send it.
        params.put(Constants.PR_MAPPER_IMPL_NAME, "");
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');

                params.put(kv.substring(0, index),
                        kv.substring(index + 1));
            }
        }
        sendResponse(0, null, params, resp);
        return;
    }

    private synchronized void getMapperInstConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does mapper instance exist?
        if (mProcessor.getMapperInsts().containsKey(id) == false) {
            sendResponse(
                    ERROR,
                    new EMapperNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_MAPPER_NOT_FOUND", id)).toString(),
                    null, resp);
            return;
        }

        ILdapMapper mapperInst = mProcessor.getMapperInstance(id);
        Vector<String> configParams = mapperInst.getInstanceParams();
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_MAPPER_IMPL_NAME,
                getMapperPluginName(mapperInst));
        // implName is always required so always send it.
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');

                params.put(kv.substring(0, index),
                        kv.substring(index + 1));
            }
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void modMapperInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // Does the manager instance exist?
        if (!mProcessor.getMapperInsts().containsKey(id)) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_INST_ID", id),
                    null, resp);
            return;
        }

        // get new implementation (same or different.)
        String implname = req.getParameter(Constants.PR_MAPPER_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ADD_MISSING_PARAMS"), null, resp);
            return;
        }
        // get plugin for implementation
        MapperPlugin plugin =
                mProcessor.getMapperPlugins().get(implname);

        if (plugin == null) {
            sendResponse(
                    ERROR,
                    new EMapperPluginNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_MAPPER_PLUGIN_NOT_FOUND",
                            implname)).toString(),
                    null, resp);
            return;
        }

        // save old instance substore params in case new one fails.

        ILdapMapper oldinst =
                mProcessor.getMapperInstance(id);
        Vector<String> oldConfigParms = oldinst.getInstanceParams();
        NameValuePairs saveParams = new NameValuePairs();

        // implName is always required so always include it it.
        saveParams.put("pluginName", implname);
        if (oldConfigParms != null) {
            for (int i = 0; i < oldConfigParms.size(); i++) {
                String kv = oldConfigParms.elementAt(i);
                int index = kv.indexOf('=');

                saveParams.put(kv.substring(0, index),
                        kv.substring(index + 1));
            }
        }

        // on to the new instance.

        // remove old substore.

        IConfigStore destStore =
                mConfig.getSubStore(mAuth.getId() +
                        ".publish.mapper");
        IConfigStore instancesConfig = destStore.getSubStore("instance");

        // create new substore.

        Vector<String> configParams = mProcessor.getMapperInstanceParams(id);

        instancesConfig.removeSubStore(id);

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put("pluginName", implname);
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');
                String key = kv.substring(0, index);
                String val = req.getParameter(key);

                if (val != null) {
                    substore.put(key, val);
                }
            }
        }

        // Instantiate an object for new implementation

        String className = plugin.getClassPath();
        ILdapMapper newMgrInst = null;

        try {
            newMgrInst = (ILdapMapper)
                    Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        }
        // initialize the mapper

        try {
            newMgrInst.init(substore);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, e.toString(getLocale(req)), null,
                    resp);
            return;
        } catch (Throwable e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, e.toString(), null,
                    resp);
            return;
        }

        // initialized ok.  commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            // clean up.
            restore(instancesConfig, id, saveParams);
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // commited ok. replace instance.

        mProcessor.getMapperInsts().put(id, new MapperProxy(true, newMgrInst));

        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_MAPPER_REPLACED", id));
        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void addRulePlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // is the rule id unique?
        if (mProcessor.getRulePlugins().containsKey(id)) {
            sendResponse(
                    ERROR,
                    new ELdapException(CMS.getUserMessage("CMS_LDAP_SRVLT_ILL_PLUGIN_ID", id)).toString(getLocale(req)),
                    null, resp);
            return;
        }

        String classPath = req.getParameter(Constants.PR_RULE_CLASS);

        if (classPath == null) {
            sendResponse(ERROR, CMS.getUserMessage("CMS_LDAP_SRVLT_NULL_CLASS"), null, resp);
            return;
        }

        IConfigStore destStore = null;

        destStore = mConfig.getSubStore(
                    mAuth.getId() + ".publish.rule");
        IConfigStore instancesConfig = destStore.getSubStore("impl");

        // Does the class exist?
        Class<?> newImpl = null;

        try {
            newImpl = Class.forName(classPath);
        } catch (ClassNotFoundException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NO_CLASS"), null, resp);
            return;
        } catch (IllegalArgumentException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NO_CLASS"), null, resp);
            return;
        }

        // is the class an ILdapRule?
        try {
            if (ILdapRule.class.isAssignableFrom(newImpl) == false) {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_CLASS", classPath), null,
                        resp);
                return;
            }
        } catch (NullPointerException e) { // unlikely, only if newImpl null.
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_CLASS", classPath), null, resp);
            return;
        }

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put(Constants.PR_RULE_CLASS, classPath);

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // add rule to registry.
        RulePlugin plugin = new RulePlugin(id, classPath);

        mProcessor.getRulePlugins().put(id, plugin);
        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_RULE_PLUG_ADDED", id));

        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void addRuleInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }
        if (!isValidID(id)) {
            sendResponse(ERROR, "Invalid ID '" + id + "'",
                    null, resp);
            return;
        }

        if (mProcessor.getRuleInsts().containsKey(id)) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_INST_ID", id),
                    null, resp);
            return;
        }

        // get required parameters
        String implname = req.getParameter(
                Constants.PR_RULE_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ADD_MISSING_PARAMS"), null, resp);
            return;
        }

        // check if implementation exists.
        RulePlugin plugin =
                mProcessor.getRulePlugins().get(implname);

        if (plugin == null) {
            sendResponse(
                    ERROR,
                    new EPublisherPluginNotFound(CMS.getUserMessage(getLocale(req),
                            "CMS_LDAP_PUBLISHER_PLUGIN_NOT_FOUND", implname)).toString(),
                    null, resp);
            return;
        }

        Vector<String> configParams = mProcessor.getRuleDefaultParams(implname);

        IConfigStore destStore =
                mConfig.getSubStore(mAuth.getId()
                        + ".publish.rule");
        IConfigStore instancesConfig =
                destStore.getSubStore("instance");
        IConfigStore substore = instancesConfig.makeSubStore(id);

        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');
                String val = req.getParameter(kv.substring(0, index));

                if (val == null) {
                    substore.put(kv.substring(0, index),
                            kv.substring(index + 1));
                } else {
                    if (val.equals(NOMAPPER))
                        val = "";
                    substore.put(kv.substring(0, index),
                            val);
                }
            }
        }
        substore.put("pluginName", implname);

        // Instantiate an object for this implementation
        String className = plugin.getClassPath();
        ILdapRule ruleInst = null;

        try {
            ruleInst = (ILdapRule) Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        }

        // initialize the rule
        try {
            ruleInst.init(mProcessor, substore);
            ruleInst.setInstanceName(id);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        } catch (Throwable e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR, e.toString(), null, resp);
            return;
        }

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            // clean up.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }
        // inited and commited ok. now add manager instance to list.
        mProcessor.getRuleInsts().put(id, ruleInst);

        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_RULE_INST_ADDED", id));

        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_RULE_IMPL_NAME, implname);
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void listRulePlugins(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mProcessor.getRulePlugins().keys();

        while (e.hasMoreElements()) {
            String name = e.nextElement();
            RulePlugin value = mProcessor.getRulePlugins().get(name);
            // get Description
            String c = value.getClassPath();
            String desc = "unknown";

            try {
                ILdapRule lp = (ILdapRule)
                        Class.forName(c).newInstance();

                desc = lp.getDescription();
            } catch (Exception exp) {
            }
            params.put(name, value.getClassPath() + "," + desc);
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void listRuleInsts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mProcessor.getRuleInsts().keys();

        for (; e.hasMoreElements();) {
            String name = e.nextElement();
            ILdapRule value = mProcessor.getRuleInsts().get(name);
            String enabled = value.enabled() ? "enabled" : "disabled";

            params.put(name, value.getInstanceName() + ";visible;" + enabled);
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    public String getRulePluginName(ILdapRule rule) {
        IConfigStore cs = rule.getConfigStore();

        try {
            return cs.getString("pluginName", "");
        } catch (EBaseException e) {
            return "";
        }
    }

    private synchronized void delRulePlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does rule exist?
        if (mProcessor.getRulePlugins().containsKey(id) == false) {
            sendResponse(ERROR,
                    new ERulePluginNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_RULE_PLUGIN_NOT_FOUND", id))
                            .toString(),
                    null, resp);
            return;
        }

        // first check if any instances from this rule
        // DON'T remove rule if any instance
        for (Enumeration<ILdapRule> e = mProcessor.getRuleInsts().elements(); e.hasMoreElements();) {
            ILdapRule rule = e.nextElement();

            if (id.equals(getRulePluginName(rule))) {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_IN_USE"), null, resp);
                return;
            }
        }

        // then delete this rule
        mProcessor.getRulePlugins().remove(id);

        IConfigStore destStore =
                mConfig.getSubStore(
                        mAuth.getId() + ".rule");
        IConfigStore instancesConfig = destStore.getSubStore("impl");

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void delRuleInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // prevent deletion of admin and agent.

        // does rule instance exist?
        if (mProcessor.getRuleInsts().containsKey(id) == false) {
            sendResponse(ERROR,
                    new ERuleNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_RULE_NOT_FOUND", id)).toString(),
                    null, resp);
            return;
        }

        // only remove from memory
        // cannot shutdown because we don't keep track of whether it's
        // being used.
        mProcessor.getRuleInsts().remove(id);

        // remove the configuration.
        IConfigStore destStore =
                mConfig.getSubStore(
                        mAuth.getId() + ".publish.rule");
        IConfigStore instancesConfig = destStore.getSubStore("instance");

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void getRuleConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
        String implname = req.getParameter(Constants.RS_ID);

        if (implname == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        Vector<String> configParams = mProcessor.getRuleDefaultParams(implname);
        NameValuePairs params = new NameValuePairs();

        // implName is always required so always send it.
        params.put(Constants.PR_RULE_IMPL_NAME, "");
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');

                params.put(kv.substring(0, index),
                        kv.substring(index + 1));
            }
        }
        sendResponse(0, null, params, resp);
        return;
    }

    private synchronized void getRuleInstConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does rule instance exist?
        if (mProcessor.getRuleInsts().containsKey(id) == false) {
            sendResponse(ERROR,
                    new ERuleNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_RULE_NOT_FOUND", id)).toString(),
                    null, resp);
            return;
        }

        ILdapRule ruleInst = mProcessor.getRuleInsts().get(id);
        Vector<String> configParams = ruleInst.getInstanceParams();
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_RULE_IMPL_NAME,
                getRulePluginName(ruleInst));
        // implName is always required so always send it.
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');

                params.put(kv.substring(0, index),
                        kv.substring(index + 1));
            }
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void modRuleInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // Does the manager instance exist?
        if (!mProcessor.getRuleInsts().containsKey(id)) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_INST_ID", id),
                    null, resp);
            return;
        }

        // get new implementation (same or different.)
        String implname = req.getParameter(Constants.PR_RULE_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ADD_MISSING_PARAMS"), null, resp);
            return;
        }

        // get plugin for implementation
        RulePlugin plugin =
                mProcessor.getRulePlugins().get(implname);

        if (plugin == null) {
            sendResponse(ERROR,
                    //new ERulePluginNotFound(implname).toString(getLocale(req)),
                    "",
                    null, resp);
            return;
        }

        // save old instance substore params in case new one fails.

        ILdapRule oldinst =
                mProcessor.getRuleInsts().get(id);
        Vector<String> oldConfigParms = oldinst.getInstanceParams();
        NameValuePairs saveParams = new NameValuePairs();

        // implName is always required so always include it it.
        saveParams.put("pluginName", implname);
        if (oldConfigParms != null) {
            for (int i = 0; i < oldConfigParms.size(); i++) {
                String kv = oldConfigParms.elementAt(i);
                int index = kv.indexOf('=');

                saveParams.put(kv.substring(0, index),
                        kv.substring(index + 1));
            }
        }

        // on to the new instance.

        // remove old substore.

        IConfigStore destStore =
                mConfig.getSubStore(
                        mAuth.getId() + ".publish.rule");
        IConfigStore instancesConfig = destStore.getSubStore("instance");

        // create new substore.

        Vector<String> configParams = mProcessor.getRuleDefaultParams(implname);

        instancesConfig.removeSubStore(id);

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put("pluginName", implname);
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');
                String key = kv.substring(0, index);
                String val = req.getParameter(key);

                if (val == null) {
                    substore.put(key,
                            kv.substring(index + 1));
                } else {
                    if (val.equals(NOMAPPER))
                        val = "";
                    substore.put(key, val);
                }
            }
        }

        // Instantiate an object for new implementation

        String className = plugin.getClassPath();
        ILdapRule newRuleInst = null;

        try {
            newRuleInst = (ILdapRule) Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        }

        // initialize the rule

        try {
            newRuleInst.init(mProcessor, substore);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        } catch (Throwable e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, e.toString(), null, resp);
            return;
        }

        // initialized ok.  commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            // clean up.
            restore(instancesConfig, id, saveParams);
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // commited ok. replace instance.

        mProcessor.getRuleInsts().put(id, newRuleInst);

        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_RULE_INST_REP", id));
        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void addPublisherPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // is the manager id unique?
        if (mProcessor.getPublisherPlugins().containsKey(id)) {
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_PLUGIN_ID", id))
                            .toString(),
                    null, resp);
            return;
        }

        String classPath = req.getParameter(Constants.PR_PUBLISHER_CLASS);

        if (classPath == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NULL_CLASS"), null, resp);
            return;
        }

        IConfigStore destStore = null;

        destStore = mConfig.getSubStore(
                    mAuth.getId() + ".publish.publisher");
        IConfigStore instancesConfig = destStore.getSubStore("impl");

        // Does the class exist?
        Class<?> newImpl = null;

        try {
            newImpl = Class.forName(classPath);
        } catch (ClassNotFoundException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NO_CLASS"), null, resp);
            return;
        } catch (IllegalArgumentException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_NO_CLASS"), null, resp);
            return;
        }

        // is the class an ILdapPublisher?
        try {
            if (ILdapPublisher.class.isAssignableFrom(newImpl) == false) {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_CLASS", classPath), null,
                        resp);
                return;
            }
        } catch (NullPointerException e) { // unlikely, only if newImpl null.
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_CLASS", classPath), null, resp);
            return;
        }

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put(Constants.PR_PUBLISHER_CLASS, classPath);

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // add publisher to registry.
        PublisherPlugin plugin = new PublisherPlugin(id, classPath);

        mProcessor.getPublisherPlugins().put(id, plugin);
        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_PUB_PLUG_ADDED", id));

        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void addPublisherInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        if (!isValidID(id)) {
            sendResponse(ERROR, "Invalid ID '" + id + "'",
                    null, resp);
            return;
        }

        if (mProcessor.getPublisherInsts().containsKey(id)) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_INST_ID", id),
                    null, resp);
            return;
        }

        // get required parameters
        String implname = req.getParameter(
                Constants.PR_PUBLISHER_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ADD_MISSING_PARAMS"), null, resp);
            return;
        }

        // check if implementation exists.
        PublisherPlugin plugin =
                mProcessor.getPublisherPlugins().get(implname);

        if (plugin == null) {
            sendResponse(
                    ERROR,
                    new EPublisherPluginNotFound(CMS.getUserMessage(getLocale(req),
                            "CMS_LDAP_PUBLISHER_PLUGIN_NOT_FOUND", implname)).toString(),
                    null, resp);
            return;
        }

        Vector<String> configParams = mProcessor.getPublisherDefaultParams(implname);

        IConfigStore destStore =
                mConfig.getSubStore(mAuth.getId() + ".publish.publisher");
        IConfigStore instancesConfig = destStore.getSubStore("instance");
        IConfigStore substore = instancesConfig.makeSubStore(id);

        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');
                String val = null;

                if (index == -1) {
                    val = req.getParameter(kv);
                } else {
                    val = req.getParameter(kv.substring(0, index));
                }
                if (val == null) {
                    if (index == -1) {
                        substore.put(kv, "");
                    } else {
                        substore.put(kv.substring(0, index),
                                kv.substring(index + 1));
                    }
                } else {
                    if (index == -1) {
                        substore.put(kv, val);
                    } else {
                        substore.put(kv.substring(0, index),
                                val);
                    }
                }
            }
        }
        substore.put("pluginName", implname);

        // Instantiate an object for this implementation
        String className = plugin.getClassPath();
        ILdapPublisher publisherInst = null;

        try {
            publisherInst = (ILdapPublisher) Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        }

        // initialize the publisher
        try {
            publisherInst.init(substore);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        } catch (Throwable e) {
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR, e.toString(), null, resp);
            return;
        }

        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            // clean up.
            instancesConfig.removeSubStore(id);
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // inited and commited ok. now add manager instance to list.
        mProcessor.getPublisherInsts().put(id, new PublisherProxy(true, publisherInst));

        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_PUB_INST_ADDED", id));

        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_PUBLISHER_IMPL_NAME, implname);
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void listPublisherPlugins(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mProcessor.getPublisherPlugins().keys();

        while (e.hasMoreElements()) {
            String name = e.nextElement();
            PublisherPlugin value = mProcessor.getPublisherPlugins().get(name);
            // get Description
            String c = value.getClassPath();
            String desc = "unknown";

            try {
                ILdapPublisher lp = (ILdapPublisher)
                        Class.forName(c).newInstance();

                desc = lp.getDescription();
            } catch (Exception exp) {
            }
            params.put(name, value.getClassPath() + "," + desc);
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    public String getPublisherPluginName(ILdapPublisher pub) {
        IConfigStore cs = pub.getConfigStore();

        try {
            return cs.getString("pluginName", "");
        } catch (EBaseException e) {
            return "";
        }
    }

    private synchronized void listPublisherInsts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = mProcessor.getPublisherInsts().keys();

        for (; e.hasMoreElements();) {
            String name = e.nextElement();
            ILdapPublisher value = mProcessor.getPublisherInstance(name);

            if (value == null)
                continue;
            params.put(name, getPublisherPluginName(value) + ";visible");
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void delPublisherPlugin(HttpServletRequest req,
            HttpServletResponse resp, String scope) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does publisher exist?
        if (mProcessor.getPublisherPlugins().containsKey(id) == false) {
            sendResponse(
                    ERROR,
                    new EPublisherPluginNotFound(CMS.getUserMessage(getLocale(req),
                            "CMS_LDAP_PUBLISHER_PLUGIN_NOT_FOUND", id)).toString(),
                    null, resp);
            return;
        }

        // first check if any instances from this publisher
        // DON'T remove publisher if any instance
        for (Enumeration<String> e = mProcessor.getPublisherInsts().keys(); e.hasMoreElements();) {
            String name = e.nextElement();
            ILdapPublisher publisher =
                    mProcessor.getPublisherInstance(name);

            if (id.equals(getPublisherPluginName(publisher))) {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_IN_USE"), null, resp);
                return;
            }
        }

        // then delete this publisher
        mProcessor.getPublisherPlugins().remove(id);

        IConfigStore destStore =
                mConfig.getSubStore(mAuth.getId() + ".publish.publisher");
        IConfigStore instancesConfig = destStore.getSubStore("impl");

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    private synchronized void delPublisherInst(HttpServletRequest req,
            HttpServletResponse resp, String scope) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // prevent deletion of admin and agent.

        // does publisher instance exist?
        if (mProcessor.getPublisherInsts().containsKey(id) == false) {
            sendResponse(ERROR,
                    new EPublisherNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_PUBLISHER_NOT_FOUND", id))
                            .toString(),
                    null, resp);
            return;
        }

        // only remove from memory
        // cannot shutdown because we don't keep track of whether it's
        // being used.
        mProcessor.getPublisherInsts().remove(id);

        // remove the configuration.
        IConfigStore destStore =
                mConfig.getSubStore(mAuth.getId() + ".publish.publisher");
        IConfigStore instancesConfig = destStore.getSubStore("instance");

        instancesConfig.removeSubStore(id);
        // commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }
        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    /**
     * used for getting the required configuration parameters (with
     * possible default values) for a particular plugin
     * implementation name specified in the RS_ID. Actually, there is
     * no logic in here to set any default value here...there's no
     * default value for any parameter in this publishing subsystem
     * at this point. Later, if we do have one (or some), it can be
     * added. The interface remains the same.
     */
    private synchronized void getConfig(HttpServletRequest req,
            HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {

        String implname = req.getParameter(Constants.RS_ID);

        if (implname == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        Vector<String> configParams = mProcessor.getPublisherDefaultParams(implname);
        NameValuePairs params = new NameValuePairs();

        // implName is always required so always send it.
        params.put(Constants.PR_PUBLISHER_IMPL_NAME, "");
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');

                if (index == -1) {
                    params.put(kv, "");
                } else {
                    params.put(kv.substring(0, index),
                            kv.substring(index + 1));
                }
            }
        }
        sendResponse(0, null, params, resp);
        return;
    }

    private synchronized void getInstConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // does publisher instance exist?
        if (mProcessor.getPublisherInsts().containsKey(id) == false) {
            sendResponse(ERROR,
                    new EPublisherNotFound(CMS.getUserMessage(getLocale(req), "CMS_LDAP_PUBLISHER_NOT_FOUND", id))
                            .toString(),
                    null, resp);
            return;
        }

        ILdapPublisher publisherInst = mProcessor.getPublisherInstance(id);
        Vector<String> configParams = publisherInst.getInstanceParams();
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_PUBLISHER_IMPL_NAME,
                getPublisherPluginName(publisherInst));
        // implName is always required so always send it.
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');

                params.put(kv.substring(0, index),
                        kv.substring(index + 1));
            }
        }

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    /**
     * Modify publisher instance.
     * This will actually create a new instance with new configuration
     * parameters and replace the old instance, if the new instance
     * created and initialized successfully.
     * The old instance is left running. so this is very expensive.
     * Restart of server recommended.
     */
    private synchronized void modPublisherInst(HttpServletRequest req,
            HttpServletResponse resp, String scope)
            throws ServletException, IOException, EBaseException {

        // expensive operation.

        String id = req.getParameter(Constants.RS_ID);

        if (id == null) {
            //System.out.println("SRVLT_NULL_RS_ID");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_NULL_RS_ID"),
                    null, resp);
            return;
        }

        // Does the manager instance exist?
        if (!mProcessor.getPublisherInsts().containsKey(id)) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ILL_INST_ID", id),
                    null, resp);
            return;
        }

        // get new implementation (same or different.)
        String implname = req.getParameter(Constants.PR_PUBLISHER_IMPL_NAME);

        if (implname == null) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_LDAP_SRVLT_ADD_MISSING_PARAMS"), null, resp);
            return;
        }

        // get plugin for implementation
        PublisherPlugin plugin =
                mProcessor.getPublisherPlugins().get(implname);

        if (plugin == null) {
            sendResponse(
                    ERROR,
                    new EPublisherPluginNotFound(CMS.getUserMessage(getLocale(req),
                            "CMS_LDAP_PUBLISHER_PLUGIN_NOT_FOUND", implname)).toString(),
                    null, resp);
            return;
        }

        // save old instance substore params in case new one fails.

        ILdapPublisher oldinst = mProcessor.getPublisherInstance(id);
        Vector<String> oldConfigParms = oldinst.getInstanceParams();
        NameValuePairs saveParams = new NameValuePairs();
        String pubType = "";

        // implName is always required so always include it it.
        saveParams.put("pluginName", implname);
        if (oldConfigParms != null) {
            for (int i = 0; i < oldConfigParms.size(); i++) {
                String kv = oldConfigParms.elementAt(i);
                int index = kv.indexOf('=');
                if (index > -1) {
                    if (kv.substring(0, index).equalsIgnoreCase("caObjectClass")) {
                        pubType = "cacert";
                    } else if (kv.substring(0, index).equalsIgnoreCase("crlObjectClass")) {
                        pubType = "crl";
                    }

                    saveParams.put(kv.substring(0, index),
                            kv.substring(index + 1));
                }
            }
        }

        // on to the new instance.

        // remove old substore.

        IConfigStore destStore =
                mConfig.getSubStore(mAuth.getId() + ".publish.publisher");
        IConfigStore instancesConfig = destStore.getSubStore("instance");

        // get objects added and deleted
        if (pubType.equals("cacert")) {
            saveParams.put("caObjectClassAdded", instancesConfig.getString(id + ".caObjectClassAdded", ""));
            saveParams.put("caObjectClassDeleted", instancesConfig.getString(id + ".caObjectClassDeleted", ""));
        } else if (pubType.equals("crl")) {
            saveParams.put("crlObjectClassAdded", instancesConfig.getString(id + ".crlObjectClassAdded", ""));
            saveParams.put("crlObjectClassDeleted", instancesConfig.getString(id + ".crlObjectClassDeleted", ""));
        }

        // create new substore.

        Vector<String> configParams = mProcessor.getPublisherInstanceParams(id);

        instancesConfig.removeSubStore(id);

        IConfigStore substore = instancesConfig.makeSubStore(id);

        substore.put("pluginName", implname);
        if (configParams != null) {
            for (int i = 0; i < configParams.size(); i++) {
                String kv = configParams.elementAt(i);
                int index = kv.indexOf('=');
                String key = kv.substring(0, index);
                String val = req.getParameter(key);

                if (val != null) {
                    substore.put(key, val);
                }
            }
        }

        // process any changes to the ldap object class definitions
        if (pubType.equals("cacert")) {
            processChangedOC(saveParams, substore, "caObjectClass");
            substore.put("pubtype", "cacert");
        }

        if (pubType.equals("crl")) {
            processChangedOC(saveParams, substore, "crlObjectClass");
            substore.put("pubtype", "crl");
        }

        // Instantiate an object for new implementation

        String className = plugin.getClassPath();
        ILdapPublisher newMgrInst = null;

        try {
            newMgrInst = (ILdapPublisher) Class.forName(className).newInstance();
        } catch (ClassNotFoundException e) {
            // cleanup
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (InstantiationException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        } catch (IllegalAccessException e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR,
                    new ELdapException(CMS.getUserMessage(getLocale(req), "CMS_LDAP_FAIL_LOAD_CLASS", className))
                            .toString(),
                    null, resp);
            return;
        }

        // initialize the publisher

        try {
            newMgrInst.init(substore);
        } catch (EBaseException e) {
            // don't commit in this case and cleanup the new substore.
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, e.toString(getLocale(req)), null, resp);
            return;
        } catch (Throwable e) {
            restore(instancesConfig, id, saveParams);
            sendResponse(ERROR, e.toString(), null, resp);
            return;
        }

        // initialized ok.  commiting
        try {
            mConfig.commit(true);
        } catch (EBaseException e) {
            // clean up.
            restore(instancesConfig, id, saveParams);
            //System.out.println("SRVLT_FAIL_COMMIT");
            sendResponse(ERROR,
                    CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_COMMIT_FAILED"),
                    null, resp);
            return;
        }

        // commited ok. replace instance.

        mProcessor.getPublisherInsts().put(id, new PublisherProxy(true, newMgrInst));

        mProcessor.log(ILogger.LL_INFO,
                CMS.getLogMessage("ADMIN_SRVLT_PUB_INST_REP", id));

        NameValuePairs params = new NameValuePairs();

        sendResponse(SUCCESS, null, params, resp);
        return;
    }

    // convenience function - takes list1, list2.  Returns what is in list1
    // but not in list2
    private String[] getExtras(String[] list1, String[] list2) {
        Vector<String> extras = new Vector<String>();
        for (int i = 0; i < list1.length; i++) {
            boolean match = false;
            for (int j = 0; j < list2.length; j++) {
                if ((list1[i].trim()).equalsIgnoreCase(list2[j].trim())) {
                    match = true;
                    break;
                }
            }
            if (!match)
                extras.add(list1[i].trim());
        }

        return extras.toArray(new String[extras.size()]);
    }

    // convenience function - takes list1, list2.  Concatenates the two
    // lists removing duplicates
    private String[] joinLists(String[] list1, String[] list2) {
        Vector<String> sum = new Vector<String>();
        for (int i = 0; i < list1.length; i++) {
            sum.add(list1[i]);
        }

        for (int i = 0; i < list2.length; i++) {
            boolean match = false;
            for (int j = 0; j < list1.length; j++) {
                if ((list2[i].trim()).equalsIgnoreCase(list1[j].trim())) {
                    match = true;
                    break;
                }
            }
            if (!match)
                sum.add(list2[i].trim());
        }

        return sum.toArray(new String[sum.size()]);
    }

    // convenience funtion. Takes a string array and delimiter
    // and returns a String with the concatenation
    private static String join(String[] s, String delimiter) {
        if (s.length == 0)
            return "";

        StringBuffer buffer = new StringBuffer(s[0]);
        if (s.length > 1) {
            for (int i = 1; i < s.length; i++) {
                buffer.append(delimiter + s[i].trim());
            }
        }
        return buffer.toString();
    }

    private void processChangedOC(NameValuePairs saveParams, IConfigStore newstore, String objName) {
        String newOC = null, oldOC = null;
        String oldAdded = null, oldDeleted = null;

        try {
            newOC = newstore.getString(objName);
        } catch (Exception e) {
        }

        oldOC = saveParams.get(objName);
        oldAdded = saveParams.get(objName + "Added");
        oldDeleted = saveParams.get(objName + "Deleted");

        if ((oldOC == null) || (newOC == null))
            return;
        if (oldOC.equalsIgnoreCase(newOC))
            return;

        String[] oldList = oldOC.split(",");
        String[] newList = newOC.split(",");
        String[] deletedList = getExtras(oldList, newList);
        String[] addedList = getExtras(newList, oldList);

        // CMS.debug("addedList = " + join(addedList, ","));
        // CMS.debug("deletedList = " + join(deletedList, ","));

        if ((addedList.length == 0) && (deletedList.length == 0))
            return; // no changes

        if (oldAdded != null) {
            // CMS.debug("oldAdded is " + oldAdded);
            String[] oldAddedList = oldAdded.split(",");
            addedList = joinLists(addedList, oldAddedList);
        }

        if (oldDeleted != null) {
            // CMS.debug("oldDeleted is " + oldDeleted);
            String[] oldDeletedList = oldDeleted.split(",");
            deletedList = joinLists(deletedList, oldDeletedList);
        }

        String[] addedList1 = getExtras(addedList, deletedList);
        String[] deletedList1 = getExtras(deletedList, addedList);

        //create the final strings and write to config
        String addedListStr = join(addedList1, ",");
        String deletedListStr = join(deletedList1, ",");

        CMS.debug("processChangedOC: added list is " + addedListStr);
        CMS.debug("processChangedOC: deleted list is " + deletedListStr);

        newstore.put(objName + "Added", addedListStr);
        newstore.put(objName + "Deleted", deletedListStr);
    }

    // convenience routine.
    private static void restore(IConfigStore store,
            String id, NameValuePairs saveParams) {
        store.removeSubStore(id);
        IConfigStore rstore = store.makeSubStore(id);

        for (String key : saveParams.keySet()) {
            String value = saveParams.get(key);

            if (value != null)
                rstore.put(key, value);
        }
    }

    private String dashes(int len) {
        String dashes = "...................................................";

        if (len <= 0)
            return "";
        String new1 = dashes.substring(0, len);

        return new1;
    }

    /**
     * logs an entry in the log file.
     */
    public void log(int level, String msg) {
        if (mLogger == null)
            return;
        mLogger.log(ILogger.EV_SYSTEM,
                ILogger.S_LDAP, level, "PublishingAdminServlet: " + msg);
    }
}
