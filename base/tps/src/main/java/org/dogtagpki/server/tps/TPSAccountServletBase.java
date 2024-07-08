package org.dogtagpki.server.tps;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.rest.v2.AccountServletBase;

import com.netscape.certsrv.account.Account;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;

public class TPSAccountServletBase extends AccountServletBase {
    TPSEngine engine = TPSEngine.getInstance();
    TPSEngineConfig configStore = engine.getConfig();

    @Override
    protected Account createAccount(Principal principal) {
        Account account = super.createAccount(principal);
        try {
            // determine accessible components based on roles
            Collection<String> components = new HashSet<>();

            Collection<String> roles = account.getRoles();

            if (roles.contains("Administrators")) {
                String values = configStore.getString("target.configure.list", "");
                if (!StringUtils.isEmpty(values)) {
                    components.addAll(Arrays.asList(values.split(",")));
                }

                // admin always has access to general configuration and audit logging
                components.add("Generals");
                components.add("Audit_Logging");

            }

            if (roles.contains("TPS Agents")) {
                String values = configStore.getString("target.agent_approve.list", "");
                if (!StringUtils.isEmpty(values)) {
                    components.addAll(Arrays.asList(values.split(",")));
                }
            }

            account.setAttribute("components", StringUtils.join(components, ","));

        } catch (EBaseException e) {
            logger.error("TPSAccountService: " + e.getMessage(), e);
            throw new PKIException(e);
        }

        return account;
    }
}
