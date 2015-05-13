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

package org.dogtagpki.server.tps.mapping;

import java.util.HashMap;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.registry.IPluginInfo;
import com.netscape.certsrv.registry.IPluginRegistry;

/**
 * mappingResolverManager is a class for mapping resolver plugin
 * management
 *
 * @author cfu
 */
public class MappingResolverManager
{
    private static final String TOKEN_MAPPING_RESOLVER_TYPE = "tpsMappingResolver";
    public static final String PROP_RESOLVER_LIST = "list";
    public static final String PROP_RESOLVER_CLASS_ID = "class_id";

    protected static final String MAPPING_RESOLVER_CFG = "mappingResolver";
    protected IPluginRegistry registry = null;
    protected HashMap<String, BaseMappingResolver> mappingResolvers = null;

    public MappingResolverManager() {
        mappingResolvers = new HashMap<String, BaseMappingResolver>();
    }

    /**
     * initializes all mapping resolver plugin instances specified in
     * <instance-name>/conf/registry.cfg
     *
     * configuration e.g.
     *
     * registry.cfg:
     * types=tpsMappingResolver
     * tpsMappingResolver.ids=mappingTokenProfileResolverImpl
     * tpsMappingResolver.mappingTokenProfileResolverImpl.class=org.dogtagpki.server.tps.mapping.mappingResolver
     * tpsMappingResolver.mappingTokenProfileResolverImpl.desc=Mapping-based Token profile resolver
     * tpsMappingResolver.mappingTokenProfileResolverImpl.name=Mapping-based Token profile resolver
     *
     * CS.cfg :
     * registry.file=/var/lib/pki/pki-tomcat/conf/tps/registry.cfg
     * mappingResolver.list=formatMappingResolver,enrollMappingResolver,pinResetMappingResolver
     * mappingResolver.formatMappingResolver.class_id=mappingProfileResolverImpl
     * mappingResolver.formatMappingResolver.[plugin-specific configuration]
     *
     * op.format.mappingResolver=formatMappingResolver
     * ...
     * op.enroll.mappingResolver=enrollMappingResolver
     *
     * Note: "none" indicates no resolver plugin applied
     * op.format.mappingResolver=none
     */
    public void initMappingResolverInstances()
            throws EBaseException {
        String method = "mappingResolverManager.initMappingResolverInstance:";
        CMS.debug(method + " begins");
        IConfigStore conf = CMS.getConfigStore();
        registry = (IPluginRegistry) CMS.getSubsystem(CMS.SUBSYSTEM_REGISTRY);
        if (registry == null) {
            CMS.debug(method + " registry null");
            return;
        }

        IConfigStore prConf = conf.getSubStore(MAPPING_RESOLVER_CFG);
        String profileList = prConf.getString(PROP_RESOLVER_LIST, "");

        for (String prInst : profileList.split(",")) {
            String classID = prConf.getString(prInst + "." + PROP_RESOLVER_CLASS_ID);
            CMS.debug(method + " initializing classID=" + classID);
            IPluginInfo resolverInfo =
                    registry.getPluginInfo(TOKEN_MAPPING_RESOLVER_TYPE, classID);
            String resolverClass = resolverInfo.getClassName();
            BaseMappingResolver resolver = null;
            try {
                resolver = (BaseMappingResolver)
                        Class.forName(resolverClass).newInstance();
            } catch (Exception e) {
                // throw Exception
                CMS.debug(method + " resolver plugin Class.forName " +
                        resolverClass + " " + e.toString());
                throw new EBaseException(e.toString());
            }
            resolver.init(prInst);
            mappingResolvers.put(prInst, resolver);
            CMS.debug(method + " resolver instance added: " + prInst);
        }
    }

    public BaseMappingResolver getResolverInstance(String name) {
        return mappingResolvers.get(name);
    }
}
