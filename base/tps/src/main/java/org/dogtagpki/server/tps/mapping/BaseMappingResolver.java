package org.dogtagpki.server.tps.mapping;

import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSEngineConfig;
import org.dogtagpki.tps.main.TPSException;

/**
 * This class implements the base TPS mapping filter Resolver instance
 *
 * @author cfu
 */
public abstract class BaseMappingResolver {
    protected TPSEngineConfig configStore;
    protected String instanceName = "";
    protected String prefix = "";

    public BaseMappingResolver() {
    }

    public void init(String instName) {
        instanceName = instName;
        prefix = MappingResolverManager.MAPPING_RESOLVER_CFG +
                "." + instanceName;
        TPSEngine engine = TPSEngine.getInstance();
        configStore = engine.getConfig();
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
