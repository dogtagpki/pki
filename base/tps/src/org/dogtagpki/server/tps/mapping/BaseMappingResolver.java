package org.dogtagpki.server.tps.mapping;

import org.dogtagpki.tps.main.TPSException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;

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
        configStore = CMS.getConfigStore();
    }

    public String getName() {
        return instanceName;
    }

    public String getPrefix() {
        return prefix;
    }

    public abstract String getResolvedMapping(FilterMappingParams pPram)
            throws TPSException;
}
