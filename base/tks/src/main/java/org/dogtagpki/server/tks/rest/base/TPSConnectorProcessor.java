package org.dogtagpki.server.tks.rest.base;

import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.tks.TKSEngine;
import org.dogtagpki.server.tks.TKSEngineConfig;
import org.dogtagpki.server.tks.TPSConnectorConfig;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorCollection;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.crypto.CryptoUtil;
/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
public class TPSConnectorProcessor {
    private static final Logger logger = LoggerFactory.getLogger(TPSConnectorProcessor.class);
    private static final int AES_SESS_KEYSIZE = 128;

    private TKSEngine engine;
    private TKSEngineConfig config;
    private UGSubsystem userGroupManager;

    public TPSConnectorProcessor(TKSEngine engine) {
        this.engine = engine;
        config = engine.getConfig();
        userGroupManager = engine.getUGSubsystem();
    }

    public TPSConnectorCollection findConnectors(String host, String port, int start, int size) {
        logger.info("TPSConnectorProcessor: Finding TPS connectors for {}:{}", host, port);

        try {

            Collection<String> tpsList = config.getTPSConnectorIDs();
            Iterator<String> entries = tpsList.iterator();

            TPSConnectorCollection response = new TPSConnectorCollection();
            int i = 0;

            // skip to the start of the page
            for (; i < start && entries.hasNext(); i++)
                entries.next();

            // return entries up to the page size
            for (; i < start + size && entries.hasNext(); i++) {
                TPSConnectorData connector = createTPSConnectorData(entries.next());

                if (host != null && !host.equals(connector.getHost())) {
                    continue;
                }

                if (port != null && !port.equals(connector.getPort())) {
                    continue;
                }

                response.addEntry(connector);
            }

            // count the total entries
            for (; entries.hasNext(); i++)
                entries.next();
            response.setTotal(i);
            return response;
        } catch (EBaseException e) {
            logger.error("TPSConnectorProcessor: Unable to find TPS connectors: " + e.getMessage(), e);
            throw new PKIException("Unable to find TPS connectors: " + e.getMessage(), e);
        }
    }

    public TPSConnectorData createConnector(Principal principal, String host, String port) {
        logger.info("TPSConnectorProcessor: Creating TPS connector for {}:{}", host, port);

        if (host == null)
            throw new BadRequestException("TPS connector host is null.");
        if (port == null)
            throw new BadRequestException("TPS connector port is null.");
        if (principal == null || principal.getName() == null || principal.getName().isBlank()) {
            throw new UnauthorizedException("User credentials not provided");
        }

        try {
            String id = getConnectorID(host, port);
            if (id != null) {
                throw new BadRequestException("TPS connection already exists. ID: " + id);
            }
            String newID = findNextConnectorID();

            TPSConnectorData newData = new TPSConnectorData();
            newData.setID(newID);
            newData.setHost(host);
            newData.setPort(port);
            newData.setUserID("TPS-" + host + "-" + port);
            saveClientData(newData);

            addToConnectorList(newID);
            config.commit(true);

            return newData;

        } catch (EBaseException e) {
            logger.error("TPSConnectorProcessor: Unable to create new TPS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to create new TPS connector: " + e.getMessage(), e);
        }
    }

    public void deleteConnector(String host, String port) {
        logger.info("TPSConnectorProcessor: Deleting TPS connector for {}:{}", host, port);

        if (host == null)
            throw new BadRequestException("TPS connector host is null.");
        if (port == null)
            throw new BadRequestException("TPS connector port is null.");

        String id;
        try {
            id = getConnectorID(host, port);
            deleteConnector(id);
        } catch (EBaseException e) {
            logger.error("TPSConnectorProcessor: Failed to delete TPS connector: " + e.getMessage(), e);
            throw new PKIException("Failed to delete TPS connector: " + e.getMessage(), e);
        }
    }

    public void deleteConnector(String id) {
        logger.info("TPSConnectorProcessor: Deleting TPS connector {}", id);

        try {
            if (StringUtils.isEmpty(id))
                throw new BadRequestException("Attempt to delete TPS connection with null or empty id");

            if (!connectorExists(id))
                return;

            deleteSharedSecret(id);
            config.removeTPSConnectorConfig(id);
            removeFromConnectorList(id);
            config.commit(true);
        } catch (EBaseException e) {
            logger.error("TPSConnectorProcessor: Failed to delete TPS connector: " + e.getMessage(), e);
            throw new PKIException("Failed to delete TPS connector: " + e.getMessage(), e);
        }
    }

    public TPSConnectorData getConnector(String id) {
        logger.info("TPSConnectorProcessor: Getting TPS connector {}", id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id))
                throw new ResourceNotFoundException("Connector " + id + " not found.");

            return createTPSConnectorData(id);

        } catch (EBaseException e) {
            logger.error("TPSConnectorProcessor: Unable to get TPS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to get TPS connector: " + e.getMessage(), e);
        }
    }

    public TPSConnectorData updateConnector(String id, TPSConnectorData data) {
        logger.info("TPSConnectorProcessor: Updatign TPS connector {}", id);

        try {
            if (id == null) {
                throw new BadRequestException("Invalid connector ID");
            }

            if (data == null) {
                throw new BadRequestException("Invalid connector data");
            }

            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // Note: we are deliberately NOT allowing the userid to be modified by the
            // admin here, because this is what maps to a user cert to retrieve the shared
            // secret
            if ((data.getUserID() != null) || (data.getNickname() != null)) {
                throw new UnauthorizedException("Cannot change userid or nickname using this interface");
            }
            TPSConnectorData curData = getConnector(id);
            curData.setHost(data.getHost());
            curData.setPort(data.getPort());

            saveClientData(curData);
            config.commit(true);

            return curData;

        } catch (EBaseException e) {
            logger.error("TPSConnectorProcessor: Unable to update TPS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to update TPS connector: " + e.getMessage(), e);
        }
    }

    public KeyData getSharedSecret(Principal principal, String id) {
        logger.info("TPSConnectorProcessor: Getting shared secret for {}", id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(principal, id);

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return null;
            }

            // get user cert
            User user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            //Create aes session sym key to wrap the shared secrt.
            SymmetricKey tempKey = CryptoUtil.createAESSessionKeyOnInternal(AES_SESS_KEYSIZE);

            if (tempKey == null) {
                return null;
            }

            List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecretWithAES(nickname, certs[certs.length -1], tempKey,getUseOAEPKeyWrap());
            byte[] wrappedSessionKey = listWrappedKeys.get(0);
            byte[] wrappedSharedSecret = listWrappedKeys.get(1);

            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSessionKey));
            keyData.setAdditionalWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSharedSecret));

            return keyData;

        } catch (Exception e) {
            logger.error("TPSConnectorProcessor: Unable to obtain shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to obtain shared secret: " + e.getMessage(), e);
        }
    }

    public KeyData createSharedSecret(Principal principal, String id) {
        logger.info("TPSConnectorProcessor: Creating shared secret for {}", id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(principal, id);

            // get user cert
            User user = userGroupManager.getUser(userid);

            logger.debug("TPSConnectorProcessor.createSharedSecret.userid: {}", userid);
            X509Certificate[] certs = user.getX509Certificates();

            String nickname = userid + " sharedSecret";

            logger.debug("TPSConnectorProcessor.createSharedSecret. nickname: {}", nickname);
            if (CryptoUtil.sharedSecretExists(nickname)) {
                throw new BadRequestException("Shared secret already exists");
            }

            CryptoUtil.createSharedSecret(nickname, KeyGenAlgorithm.AES, AES_SESS_KEYSIZE);

            TPSConnectorConfig tpsConfig = config.getTPSConnectorConfig(id);
            tpsConfig.setNickname(nickname);
            config.commit(true);

            //Create aes session sym key to wrap the shared secret.
            SymmetricKey tempKey = CryptoUtil.createAESSessionKeyOnInternal(AES_SESS_KEYSIZE);

            if (tempKey == null) {
                return null;
            }

            logger.debug("TPSConnectorProcessor.createSharedSecret. about to export shared secret: {} certs.length {}", nickname, certs.length);
            logger.debug("TPSConnectorProcessor.createSharedSecert cert: {}", certs[certs.length -1]);
            List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecret(nickname, certs[certs.length -1], tempKey, getUseOAEPKeyWrap());
            logger.debug("TPSConnectorProcessor.createSharedSecret. done exporting shared secret: {}", nickname);

            byte[] wrappedSessionKey = listWrappedKeys.get(0);
            byte[] wrappedSharedSecret = listWrappedKeys.get(1);

            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSessionKey));
            keyData.setAdditionalWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSharedSecret));

            return keyData;

        } catch (Exception e) {
            logger.error("TPSConnectorProcessor: Unable to generate and export shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to generate and export shared secret: " + e.getMessage(), e);
        }
    }

    public KeyData replaceSharedSecret(Principal principal, String id) {
        logger.info("TPSConnectorProcessor: Replacing shared secret for {}", id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(principal, id);

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                throw new BadRequestException("Cannot replace. Shared secret does not exist");
            }

            // get user cert
            User user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            CryptoUtil.deleteSharedSecret(nickname);
            CryptoUtil.createSharedSecret(nickname);

            //Create aes session sym key to wrap the shared secret.
            SymmetricKey tempKey = CryptoUtil.createAESSessionKeyOnInternal(AES_SESS_KEYSIZE);

            if (tempKey == null) {
                return null;
            }

            List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecret(nickname,certs[certs.length -1], tempKey, getUseOAEPKeyWrap());

            byte[] wrappedSessionKey = listWrappedKeys.get(0);
            byte[] wrappedSharedSecret = listWrappedKeys.get(1);

            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSessionKey));
            keyData.setAdditionalWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSharedSecret));

            return keyData;

        } catch (Exception e) {
            logger.error("TPSConnectorProcessor: Unable to replace shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to replace shared secret: " + e.getMessage(), e);
        }
    }

    public void deleteSharedSecret(String id) {
        logger.info("TPSConnectorProcessor: Deleting shared secret for {}", id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            TPSConnectorConfig tpsConfig = config.getTPSConnectorConfig(id);

            // get user
            String userid = tpsConfig.getUserID();
            if (userid.isEmpty()) {
                throw new PKIException("Bad TPS connection configuration: userid not defined");
            }

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return;
            }
            CryptoUtil.deleteSharedSecret(nickname);

            tpsConfig.setNickname("");
            config.commit(true);

        } catch (InvalidKeyException | IllegalStateException | EBaseException
                | NotInitializedException | TokenException e) {
            logger.error("TPSConnectorProcessor: Unable to delete shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to delete shared secret: " + e.getMessage(), e);
        }
    }

    private TPSConnectorData createTPSConnectorData(String tpsID) throws EBaseException {

        TPSConnectorConfig tpsConfig = config.getTPSConnectorConfig(tpsID);

        TPSConnectorData data = new TPSConnectorData();
        data.setID(tpsID);
        data.setHost(tpsConfig.getHost());
        data.setPort(tpsConfig.getPort());
        data.setUserID(tpsConfig.getUserID());
        data.setNickname(tpsConfig.getNickname());
        return data;
    }

    private String getConnectorID(String host, String port) throws EBaseException {
        Collection<String> tpsList = config.getTPSConnectorIDs();
        for (String tpsID : tpsList) {
            TPSConnectorData data = createTPSConnectorData(tpsID);
            if (data.getHost().equals(host) && data.getPort().equals(port))
                return tpsID;
        }
        return null;
    }

    private String findNextConnectorID() throws EBaseException {
        Collection<String> tpsList = config.getTPSConnectorIDs();
        Collection<String> sorted = new TreeSet<>();
        sorted.addAll(tpsList);

        int index = 0;
        while (sorted.contains(Integer.toString(index)))
            index++;
        return Integer.toString(index);
    }

    private void saveClientData(TPSConnectorData newData) {
        String id = newData.getID();
        if (StringUtils.isEmpty(id)) {
            logger.warn("TPSConnectorProcessor: Attempt to save tps connection with null or empty id");
            return;
        }

        TPSConnectorConfig tpsConfig = config.getTPSConnectorConfig(id);

        if (newData.getHost() != null)
            tpsConfig.setHost(newData.getHost());
        if (newData.getPort() != null)
            tpsConfig.setPort(newData.getPort());
        if (newData.getUserID() != null)
            tpsConfig.setUserID(newData.getUserID());
        if (newData.getNickname() != null)
            tpsConfig.setNickname(newData.getNickname());
    }

    private void addToConnectorList(String id) throws EBaseException {
        Collection<String> tpsList = config.getTPSConnectorIDs();
        Collection<String> sorted = new TreeSet<>();
        sorted.addAll(tpsList);
        sorted.add(id);
        config.setTPSConnectorIDs(sorted);
    }

    private boolean connectorExists(String id) throws EBaseException {
        Collection<String> tpsList = config.getTPSConnectorIDs();
        return tpsList.contains(id);
    }

    private void removeFromConnectorList(String id) throws EBaseException {
        Collection<String> tpsList = config.getTPSConnectorIDs();
        Collection<String> sorted = new TreeSet<>();
        sorted.addAll(tpsList);
        sorted.remove(id);
        config.setTPSConnectorIDs(sorted);
    }

    private String validateUser(Principal principal, String id) throws EBaseException {
        TPSConnectorConfig tpsConfig = config.getTPSConnectorConfig(id);
        String userid = tpsConfig.getUserID();
        if (userid.isEmpty()) {
            throw new PKIException("Bad TPS connection configuration: userid not defined");
        }

        if (principal == null || principal.getName() == null || principal.getName().isBlank()) {
            throw new UnauthorizedException("User credentials not provided");
        }

        String uid = principal.getName();
        if (!uid.equals(userid)) {
            throw new UnauthorizedException("TPS Connection belongs to another user");
        }
        return userid;
    }

    private boolean getUseOAEPKeyWrap() throws EBaseException {
        boolean useOAEPKeyWrap = config.getBoolean("keyWrap.useOAEP",false);
       logger.debug("TPSConnectorProcessor.createSharedSecret.getUseOAEPKeyWrap: {}", useOAEPKeyWrap);
       return useOAEPKeyWrap;
   }
}
