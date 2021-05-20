package org.dogtagpki.server.tks.rest;

import java.net.URI;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.tks.TKSEngine;
import org.dogtagpki.server.tks.TKSEngineConfig;
import org.dogtagpki.server.tks.TPSConnectorConfig;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorCollection;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.certsrv.system.TPSConnectorResource;
import com.netscape.certsrv.tps.cert.TPSCertResource;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class TPSConnectorService extends PKIService implements TPSConnectorResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSConnectorService.class);

    TKSEngine engine = TKSEngine.getInstance();
    TKSEngineConfig cs = engine.getConfig();

    public UGSubsystem userGroupManager = engine.getUGSubsystem();

    @Override
    public Response findConnectors(String host, String port, Integer start, Integer size) {

        logger.info("TPSConnectorService: Finding TPS connectors for " + host + ":" + port);

        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            Collection<String> tpsList = cs.getTPSConnectorIDs();
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

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start - size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start + size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start + size).build();
                response.addLink(new Link("next", uri));
            }

            return createOKResponse(response);

        } catch (EBaseException e) {
            logger.error("TPSConnectorService: Unable to find TPS connectors: " + e.getMessage(), e);
            throw new PKIException("Unable to find TPS connectors: " + e.getMessage(), e);
        }
    }

    private TPSConnectorData createTPSConnectorData(String tpsID) throws EBaseException {

        TPSConnectorConfig tpsConfig = cs.getTPSConnectorConfig(tpsID);

        TPSConnectorData data = new TPSConnectorData();
        data.setID(tpsID);
        data.setHost(tpsConfig.getHost());
        data.setPort(tpsConfig.getPort());
        data.setUserID(tpsConfig.getUserID());
        data.setNickname(tpsConfig.getNickname());

        URI uri = uriInfo.getBaseUriBuilder().path(TPSCertResource.class).path("{id}").build(tpsID);
        data.setLink(new Link("self", uri));

        return data;
    }

    @Override
    public Response getConnector(String id) {
        return createOKResponse(getConnectorData(id));
    }

    public TPSConnectorData getConnectorData(String id) {

        logger.info("TPSConnectorService: Getting TPS connector " + id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id))
                throw new ResourceNotFoundException("Connector " + id + " not found.");

            return createTPSConnectorData(id);

        } catch (EBaseException e) {
            logger.error("TPSConnectorService: Unable to get TPS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to get TPS connector: " + e.getMessage(), e);
        }
    }

    @Override
    public Response createConnector(String tpsHost, String tpsPort) {

        logger.info("TPSConnectorService: Creating TPS connector for " + tpsHost + ":" + tpsPort);

        if (tpsHost == null)
            throw new BadRequestException("TPS connector host is null.");
        if (tpsPort == null)
            throw new BadRequestException("TPS connector port is null.");

        try {
            String id = getConnectorID(tpsHost, tpsPort);
            if (id != null) {
                URI uri = uriInfo.getBaseUriBuilder().path(TPSCertResource.class)
                        .path("{id}").build(id);
                throw new BadRequestException("TPS connection already exists at " + uri.toString());
            }
            String newID = findNextConnectorID();

            TPSConnectorData newData = new TPSConnectorData();
            newData.setID(newID);
            newData.setHost(tpsHost);
            newData.setPort(tpsPort);
            newData.setUserID("TPS-" + tpsHost + "-" + tpsPort);
            URI uri = uriInfo.getBaseUriBuilder().path(TPSCertResource.class).path("{id}").build(newID);
            newData.setLink(new Link("self", uri));
            saveClientData(newData);

            addToConnectorList(newID);
            cs.commit(true);

            return createCreatedResponse(newData, uri);

        } catch (EBaseException e) {
            logger.error("TPSConnectorService: Unable to create new TPS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to create new TPS connector: " + e.getMessage(), e);
        }
    }

    @Override
    public Response modifyConnector(String id, TPSConnectorData data) {

        logger.info("TPSConnectorService: Modifying TPS connector " + id);

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
            TPSConnectorData curData = getConnectorData(id);
            curData.setHost(data.getHost());
            curData.setPort(data.getPort());

            saveClientData(curData);
            cs.commit(true);

            return createOKResponse(curData);

        } catch (EBaseException e) {
            logger.error("TPSConnectorService: Unable to modify TPS connector: " + e.getMessage(), e);
            throw new PKIException("Unable to modify TPS connector: " + e.getMessage(), e);
        }
    }

    private void saveClientData(TPSConnectorData newData) throws EBaseException {
        String id = newData.getID();
        if (StringUtils.isEmpty(id)) {
            logger.warn("TPSConnectorService: Attempt to save tps connection with null or empty id");
            return;
        }

        TPSConnectorConfig tpsConfig = cs.getTPSConnectorConfig(id);

        if (newData.getHost() != null)
            tpsConfig.setHost(newData.getHost());
        if (newData.getPort() != null)
            tpsConfig.setPort(newData.getPort());
        if (newData.getUserID() != null)
            tpsConfig.setUserID(newData.getUserID());
        if (newData.getNickname() != null)
            tpsConfig.setNickname(newData.getNickname());
    }

    @Override
    public Response deleteConnector(String id) {

        logger.info("TPSConnectorService: Deleting TPS connector " + id);

        try {
            if (StringUtils.isEmpty(id))
                throw new BadRequestException("Attempt to delete TPS connection with null or empty id");

            if (!connectorExists(id))
                return createNoContentResponse();

            deleteSharedSecret(id);
            cs.removeTPSConnectorConfig(id);
            removeFromConnectorList(id);
            cs.commit(true);

            return createNoContentResponse();

        } catch (EBaseException e) {
            logger.error("TPSConnectorService: Failed to delete TPS connector: " + e.getMessage(), e);
            throw new PKIException("Failed to delete TPS connector: " + e.getMessage(), e);
        }
    }

    @Override
    public Response deleteConnector(String host, String port) {

        logger.info("TPSConnectorService: Deleting TPS connector for " + host + ":" + port);

        if (host == null)
            throw new BadRequestException("TPS connector host is null.");
        if (port == null)
            throw new BadRequestException("TPS connector port is null.");

        String id;
        try {
            id = getConnectorID(host, port);
            deleteConnector(id);
        } catch (EBaseException e) {
            logger.error("TPSConnectorService: Failed to delete TPS connector: " + e.getMessage(), e);
            throw new PKIException("Failed to delete TPS connector: " + e.getMessage(), e);
        }

        return createNoContentResponse();
    }

    @Override
    public Response createSharedSecret(String id) {

        logger.info("TPSConnectorService: Creating shared secret for " + id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(id);

            // get user cert
            User user = userGroupManager.getUser(userid);

            logger.debug("TPSConnectorService.createSharedSecret.userid: " + userid);
            X509Certificate[] certs = user.getX509Certificates();

            String nickname = userid + " sharedSecret";

            logger.debug("TPSConnectorService.createSharedSecret. nickname: " + nickname);
            if (CryptoUtil.sharedSecretExists(nickname)) {
                throw new BadRequestException("Shared secret already exists");
            }

            CryptoUtil.createSharedSecret(nickname);

            TPSConnectorConfig tpsConfig = cs.getTPSConnectorConfig(id);
            tpsConfig.setNickname(nickname);
            cs.commit(true);

            //Create des3 session sym key to wrap the shared secret.
            SymmetricKey tempKey = CryptoUtil.createDes3SessionKeyOnInternal();

            if (tempKey == null) {
                return createNoContentResponse();
            }

            List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecret(nickname, certs[0], tempKey);

            byte[] wrappedSessionKey = listWrappedKeys.get(0);
            byte[] wrappedSharedSecret = listWrappedKeys.get(1);

            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSessionKey));
            keyData.setAdditionalWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSharedSecret));

            return createOKResponse(keyData);

        } catch (Exception  e) {
            logger.error("TPSConnectorService: Unable to generate and export shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to generate and export shared secret: " + e.getMessage(), e);
        }
    }

    private String validateUser(String id) throws EBaseException {
        TPSConnectorConfig tpsConfig = cs.getTPSConnectorConfig(id);
        String userid = tpsConfig.getUserID();
        if (userid.isEmpty()) {
            throw new PKIException("Bad TPS connection configuration: userid not defined");
        }

        Principal principal = servletRequest.getUserPrincipal();
        if (principal == null) {
            throw new UnauthorizedException("User credentials not provided");
        }

        String uid = principal.getName();
        if (!uid.equals(userid)) {
            throw new UnauthorizedException("TPS Connection belongs to another user");
        }
        return userid;
    }

    @Override
    public Response replaceSharedSecret(String id) {

        logger.info("TPSConnectorService: Replacing shared secret for " + id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(id);

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                throw new BadRequestException("Cannot replace. Shared secret does not exist");
            }

            // get user cert
            User user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            CryptoUtil.deleteSharedSecret(nickname);
            CryptoUtil.createSharedSecret(nickname);

            //Create des3 session sym key to wrap the shared secret.
            SymmetricKey tempKey = CryptoUtil.createDes3SessionKeyOnInternal();

            if (tempKey == null) {
                return createNoContentResponse();
            }

            List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecret(nickname,certs[0], tempKey);

            byte[] wrappedSessionKey = listWrappedKeys.get(0);
            byte[] wrappedSharedSecret = listWrappedKeys.get(1);

            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSessionKey));
            keyData.setAdditionalWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSharedSecret));

            return createOKResponse(keyData);

        } catch (Exception e) {
            logger.error("TPSConnectorService: Unable to replace shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to replace shared secret: " + e.getMessage(), e);
        }
    }

    @Override
    public Response deleteSharedSecret(String id) {

        logger.info("TPSConnectorService: Deleting shared secret for " + id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            TPSConnectorConfig tpsConfig = cs.getTPSConnectorConfig(id);

            // get user
            String userid = tpsConfig.getUserID();
            if (userid.isEmpty()) {
                throw new PKIException("Bad TPS connection configuration: userid not defined");
            }

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return createNoContentResponse();
            }
            CryptoUtil.deleteSharedSecret(nickname);

            tpsConfig.setNickname("");
            cs.commit(true);

            return createNoContentResponse();

        } catch (InvalidKeyException | IllegalStateException | EBaseException
                | NotInitializedException | TokenException e) {
            logger.error("TPSConnectorService: Unable to delete shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to delete shared secret: " + e.getMessage(), e);
        }
    }

    @Override
    public Response getSharedSecret(String id) {

        logger.info("TPSConnectorService: Getting shared secret for " + id);

        if (id == null)
            throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(id);

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return createNoContentResponse();
            }

            // get user cert
            User user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            //Create des3 session sym key to wrap the shared secrt.
            SymmetricKey tempKey = CryptoUtil.createDes3SessionKeyOnInternal();

            if (tempKey == null) {
                return createNoContentResponse();
            }

            List<byte[]> listWrappedKeys = CryptoUtil.exportSharedSecret(nickname, certs[0], tempKey);
            byte[] wrappedSessionKey = listWrappedKeys.get(0);
            byte[] wrappedSharedSecret = listWrappedKeys.get(1);

            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSessionKey));
            keyData.setAdditionalWrappedPrivateData(Utils.base64encodeSingleLine(wrappedSharedSecret));

            return createOKResponse(keyData);

        } catch (Exception e) {
            logger.error("TPSConnectorService: Unable to obtain shared secret: " + e.getMessage(), e);
            throw new PKIException("Unable to obtain shared secret: " + e.getMessage(), e);
        }
    }

    private boolean connectorExists(String id) throws EBaseException {
        Collection<String> tpsList = cs.getTPSConnectorIDs();
        return tpsList.contains(id);
    }

    private String getConnectorID(String host, String port) throws EBaseException {
        Collection<String> tpsList = cs.getTPSConnectorIDs();
        for (String tpsID : tpsList) {
            TPSConnectorData data = createTPSConnectorData(tpsID);
            if (data.getHost().equals(host) && data.getPort().equals(port))
                return tpsID;
        }
        return null;
    }

    private void addToConnectorList(String id) throws EBaseException {
        Collection<String> tpsList = cs.getTPSConnectorIDs();
        Collection<String> sorted = new TreeSet<>();
        sorted.addAll(tpsList);
        sorted.add(id);
        cs.setTPSConnectorIDs(sorted);
    }

    private void removeFromConnectorList(String id) throws EBaseException {
        Collection<String> tpsList = cs.getTPSConnectorIDs();
        Collection<String> sorted = new TreeSet<>();
        sorted.addAll(tpsList);
        sorted.remove(id);
        cs.setTPSConnectorIDs(sorted);
    }

    private String findNextConnectorID() throws EBaseException {
        Collection<String> tpsList = cs.getTPSConnectorIDs();
        Collection<String> sorted = new TreeSet<>();
        sorted.addAll(tpsList);

        int index = 0;
        while (sorted.contains(Integer.toString(index)))
            index++;
        return Integer.toString(index);
    }
}
