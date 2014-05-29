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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.profile;

import java.util.HashMap;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;

/**
 * TokenProfileResolverManager is a class for profile resolver plugin
 * management
 *
 * @author cfu
 */
public class TokenProfileResolverManager
{
    private static final String TOKEN_PROFILE_RESOLVER_TYPE = "tpsTokenProfileResolver";
    public static final String PROP_RESOLVER_LIST = "list";
    public static final String PROP_RESOLVER_CLASS_ID = "class_id";

    protected static final String TOKEN_PROFILE_RESOLVER_CFG = "tokenProfileResolver";
    protected IPluginRegistry registry = null;
    protected HashMap<String, BaseTokenProfileResolver> tokenProfileResolvers = null;

    public TokenProfileResolverManager() {
        tokenProfileResolvers = new HashMap<String, BaseTokenProfileResolver>();
    }

    /**
     * initializes all profile resolver plugin instances specified in
     * <instance-name>/conf/registry.cfg
     *
     * configuration e.g.
     *
     * registry.cfg:
     * types=tpsTokenProfileResolver
     * tpsProfileResolver.ids=mappingTokenProfileResolverImpl
     * tpsProfileResolver.mappingTokenProfileResolverImpl.class=org.dogtagpki.server.tps.profile.MappingTokenProfileResolver
     * tpsProfileResolver.mappingTokenProfileResolverImpl.desc=Mapping-based Token profile resolver
     * tpsProfileResolver.mappingTokenProfileResolverImpl.name=Mapping-based Token profile resolver
     *
     * CS.cfg :
     * registry.file=/var/lib/pki/pki-tomcat/conf/tps/registry.cfg
     * tokenProfileResolver.list=formatMappingResolver,enrollMappingResolver,pinResetMappingResolver
     * tokenProfileResolver.formatMappingResolver.class_id=mappingProfileResolverImpl
     * tokenProfileResolver.formatMappingResolver.[plugin-specific configuration]
     *
     * op.format.tokenProfileResolver=formatMappingResolver
     * ...
     * op.enroll.tokenProfileResolver=enrollMappingResolver
     *
     * Note: "none" indicates no resolver plugin applied
     * op.format.tokenProfileResolver=none
     */
    public void initProfileResolverInstances()
            throws EBaseException {

        CMS.debug("TokenProfileResolverManager: initProfileResolverInstances(): begins");
        IConfigStore conf = CMS.getConfigStore();
        registry = (IPluginRegistry) CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
        if (registry == null) {
            CMS.debug("TokenProfileResolverManager: initProfileResolverInstances(): registry null");
            return;
        }

        IConfigStore prConf = conf.getSubStore(TOKEN_PROFILE_RESOLVER_CFG);
        String profileList = prConf.getString(PROP_RESOLVER_LIST, "");

        for (String prInst : profileList.split(",")) {
            String classID = prConf.getString(prInst + "." + PROP_RESOLVER_CLASS_ID);
            CMS.debug("TokenProfileResolverManager: initProfileResolverInstances(): initializing classID=" + classID);
            IPluginInfo resolverInfo =
                    registry.getPluginInfo(TOKEN_PROFILE_RESOLVER_TYPE, classID);
            String resolverClass = resolverInfo.getClassName();
            BaseTokenProfileResolver resolver = null;
            try {
                resolver = (BaseTokenProfileResolver)
                        Class.forName(resolverClass).newInstance();
            } catch (Exception e) {
                // throw Exception
                CMS.debug("TokenProfileResolverManager: resolver plugin Class.forName " +
                        resolverClass + " " + e.toString());
                throw new EBaseException(e.toString());
            }
            resolver.init(prInst);
            tokenProfileResolvers.put(prInst, resolver);
            CMS.debug("TokenProfileResolverManager: initProfileResolverInstances(): resolver instance added: " + prInst);
        }
    }

    public BaseTokenProfileResolver getResolverInstance(String name) {
        return tokenProfileResolvers.get(name);
    }
}
