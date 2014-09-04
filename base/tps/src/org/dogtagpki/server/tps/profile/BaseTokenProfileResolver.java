package org.dogtagpki.server.tps.profile;

import org.dogtagpki.tps.main.TPSException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;

/**
 * This class implements the base TPS Profile Resolver instance
 *
 * @author cfu
 */
public abstract class BaseTokenProfileResolver {
    protected IConfigStore configStore = null;
    protected String instanceName = "";
    protected String prefix = "";

    public BaseTokenProfileResolver() {
    }

    public void init(String instName) {
        instanceName = instName;
        prefix = TokenProfileResolverManager.TOKEN_PROFILE_RESOLVER_CFG +
                "." + instanceName;
        configStore = CMS.getConfigStore();
    }

    public String getName() {
        return instanceName;
    }

    public String getPrefix() {
        return prefix;
    }

    public abstract String getTokenType(TokenProfileParams pPram)
            throws TPSException;
}
