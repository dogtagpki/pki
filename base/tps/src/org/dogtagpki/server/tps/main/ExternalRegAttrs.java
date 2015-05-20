package org.dogtagpki.server.tps.main;

import java.math.BigInteger;
import java.util.ArrayList;

import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;

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

    /*
     *
     * @param serialString serial number in hex
     */
    public ExternalRegCertToRecover.CertStatus getCertStatus(String serialString) throws TPSException {
        String method = "ExternalRegAttrs.getCertStatus:";
        String auditMsg = "";
        CMS.debug(method + "begins. getCertsToRecoverCount=" + getCertsToRecoverCount());
        if (serialString == null) {
            auditMsg = "parameter serialString cannnot be null";
            CMS.debug(method + auditMsg);
            throw new TPSException(method + auditMsg, TPSStatus.STATUS_ERROR_CONTACT_ADMIN);
        } else
            CMS.debug(method + "searching for serialString =" + serialString);
        if (serialString.startsWith("0x")) {
            serialString = serialString.substring(2);
        }
        BigInteger serial = new BigInteger(serialString, 16);
        CMS.debug(method + "searching for serial=" + serial);
        for (ExternalRegCertToRecover cert: certsToRecover) {
            CMS.debug(method + "cert.getSerial()=" + cert.getSerial());
            if (serial.compareTo(cert.getSerial()) == 0) {
                CMS.debug(method + " cert found... returning status: " + cert.getCertStatus().toString());
                return cert.getCertStatus();
            }
        }
        auditMsg = "cert not found in ExternalReg, status not reset";
        CMS.debug(method + auditMsg);
        // no match means cert was not one of the ExternalReg recovered certs; so don't reset
        // use UNINITIALIZED to mean not found, as all certs in externalReg must have been set by now
        return ExternalRegCertToRecover.CertStatus.UNINITIALIZED;
    }
}
