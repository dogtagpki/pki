package org.dogtagpki.server.tps.main;

import java.util.ArrayList;

import org.dogtagpki.server.authentication.AuthManagersConfig;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.tps.engine.TPSEngine;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.EngineConfig;

public class ExternalRegAttrs {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ExternalRegAttrs.class);

    public String ldapAttrNameTokenType;
    public String ldapAttrNameTokenCUID;
    public String ldapAttrNameCertsToRecover;
    public String ldapAttrNameRegistrationType;

    String tokenCUID;
    String tokenType;
    String tokenUserId;
    String tokenMSN;
    String registrationType;

    ArrayList<ExternalRegCertToRecover> certsToRecover;

    boolean isDelegation;

    public ExternalRegAttrs(String authId) {
        String method = "ExternalRegAttrs";
        org.dogtagpki.server.tps.TPSEngine engine = org.dogtagpki.server.tps.TPSEngine.getInstance();
        EngineConfig configStore = engine.getConfig();
        AuthenticationConfig authConfig = configStore.getAuthenticationConfig();
        AuthManagersConfig instancesConfig = authConfig.getAuthManagersConfig();

        String configName = null;

        try {
            configName = authId + ".externalReg.tokenTypeAttributeName";
            logger.debug(method + ": getting config: auths.instance." + configName);
            ldapAttrNameTokenType = instancesConfig.getString(configName, "tokenType");

            configName = authId + ".externalReg.cuidAttributeName";
            logger.debug(method + ": getting config: auths.instance." + configName);
            ldapAttrNameTokenCUID = instancesConfig.getString(configName, "tokenCUID");

            configName = authId + ".externalReg.certs.recoverAttributeName";
            logger.debug(method + ": getting config: auths.instance." + configName);
            ldapAttrNameCertsToRecover = instancesConfig.getString(configName, "certsToRecover");

            String RH_Delegation_Cfg = TPSEngine.CFG_EXTERNAL_REG + "." +
                    TPSEngine.CFG_ER_DELEGATION + ".enable";
            isDelegation = configStore.getBoolean(RH_Delegation_Cfg, false);

            configName = authId + ".externalReg.registrationTypeAttributeName";
            logger.debug(method + ": getting config: auths.instance." + configName);
            ldapAttrNameRegistrationType = instancesConfig.getString(configName, "registrationtype");
        } catch (EBaseException e) {
            logger.warn("ExternalRegAttrs: unable to obtain certain config values. Default to be used: " + e.getMessage(), e);
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

    public void setRegistrationType(String regType) {
        registrationType = regType;
    }

    public String getRegistrationType() {
        return registrationType;
    }

}
