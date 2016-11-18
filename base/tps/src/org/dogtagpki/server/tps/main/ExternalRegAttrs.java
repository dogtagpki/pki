package org.dogtagpki.server.tps.main;

import java.util.ArrayList;

import org.dogtagpki.server.tps.engine.TPSEngine;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

public class ExternalRegAttrs {
    public String ldapAttrNameTokenType;
    public String ldapAttrNameTokenCUID;
    public String ldapAttrNameCertsToRecover;

    String tokenCUID;
    String tokenType;
    String tokenUserId;
    String tokenMSN;

    ArrayList<ExternalRegCertToRecover> certsToRecover;

    boolean isDelegation;

    public ExternalRegAttrs(String authId) {
        String method = "ExternalRegAttrs";
        IConfigStore configStore = CMS.getConfigStore();
        String configName = null;

        try {
            configName = "auths.instance." + authId + ".externalReg.tokenTypeAttributeName";
            CMS.debug(method + ": getting config: " + configName);
            ldapAttrNameTokenType = configStore.getString(configName,
                    "tokenType");

            configName = "auths.instance." + authId + ".externalReg.cuidAttributeName";
            CMS.debug(method + ": getting config: " + configName);
            ldapAttrNameTokenCUID = configStore.getString(configName,
                    "tokenCUID");

            configName = "auths.instance." + authId + ".externalReg.certs.recoverAttributeName";
            CMS.debug(method + ": getting config: " + configName);
            ldapAttrNameCertsToRecover = configStore.getString(configName,
                    "certsToRecover");

            String RH_Delegation_Cfg = TPSEngine.CFG_EXTERNAL_REG + "." +
                    TPSEngine.CFG_ER_DELEGATION + ".enable";
            isDelegation = configStore.getBoolean(RH_Delegation_Cfg, false);
        } catch (EBaseException e) {
            CMS.debug("ExternalRegAttrs: unable to obtain certain config values.  Default to be used");
        }

        certsToRecover = new ArrayList<ExternalRegCertToRecover>();
    }

    public void setTokenType(String type) {
        tokenType = type;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenCUID(String cuid) {
        tokenCUID = cuid;
    }

    public String getTokenCUID() {
        return tokenCUID;
    }

    public void setTokenUserId(String uid) {
        tokenUserId = uid;
    }

    public String getTokenUserId() {
        return tokenUserId;
    }

    public void setTokenMSN(String msn) {
        tokenMSN = msn;
    }

    public String getTokenMSN() {
        return tokenMSN;
    }

    public int getCertsToRecoverCount()
    {
        return certsToRecover.size();
    }

    public void addCertToRecover(ExternalRegCertToRecover cert)
    {
        certsToRecover.add(cert);
    }

    public ArrayList<ExternalRegCertToRecover> getCertsToRecover() {
        return certsToRecover;
    }

    public void setIsDelegation(boolean isDelegation) {
        this.isDelegation = isDelegation;
    }

    public boolean getIsDelegation() {
        return isDelegation;
    }

}
