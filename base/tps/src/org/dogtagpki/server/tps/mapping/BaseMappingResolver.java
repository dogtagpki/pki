package org.dogtagpki.server.tps.mapping;

import org.dogtagpki.tps.main.TPSException;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * This class implements the base TPS mapping filter Resolver instance
 *
 * @author cfu
 */
public abstract class BaseMappingResolver {
    protected IConfigStore configStore = null;
    protected String instanceName = "";
    protected String prefix = "";

    public BaseMappingResolver() {
    }

    public void init(String instName) {
        instanceName = instName;
        prefix = MappingResolverManager.MAPPING_RESOLVER_CFG +
                "." + instanceName;
        CMSEngine engine = CMS.getCMSEngine();
        configStore = engine.getConfigStore();
    }

    public String getName() {
        return instanceName;
    }

    public String getPrefix() {
        return prefix;
    }

    public abstract String getResolvedMapping(FilterMappingParams pPram)
            throws TPSException;

    public abstract String getResolvedMapping(FilterMappingParams mappingParams, String nameToMap)
            throws TPSException;

}
