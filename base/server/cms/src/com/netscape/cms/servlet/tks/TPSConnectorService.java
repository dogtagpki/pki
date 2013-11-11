package com.netscape.cms.servlet.tks;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.InvalidKeyFormatException;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorCollection;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.certsrv.system.TPSConnectorResource;
import com.netscape.certsrv.tps.cert.TPSCertResource;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

public class TPSConnectorService implements TPSConnectorResource {

    private static final String TPS_LIST = "tps.list";

    IConfigStore cs = CMS.getConfigStore();

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpServletRequest servletRequest;

    public final static int DEFAULT_SIZE = 20;

    public IUGSubsystem userGroupManager = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    @Override
    public TPSConnectorCollection findConnectors(Integer start, Integer size) {
        try {
            String tpsList = cs.getString(TPS_LIST, "");
            Iterator<String> entries = Arrays.asList(StringUtils.split(tpsList,",")).iterator();

            TPSConnectorCollection response = new TPSConnectorCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && entries.hasNext(); i++) entries.next();

            // return entries up to the page size
            for ( ; i<start+size && entries.hasNext(); i++) {
                response.addEntry(createTPSConnectorData(entries.next()));
            }

            // count the total entries
            for ( ; entries.hasNext(); i++) entries.next();
            response.setTotal(i);

            if (start > 0) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", Math.max(start-size, 0)).build();
                response.addLink(new Link("prev", uri));
            }

            if (start+size < i) {
                URI uri = uriInfo.getRequestUriBuilder().replaceQueryParam("start", start+size).build();
                response.addLink(new Link("next", uri));
            }

            return response;

        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Unable to get TPS connection data: " + e);
        }
    }

    private TPSConnectorData createTPSConnectorData(String tpsID) throws EBaseException {
        TPSConnectorData data = new TPSConnectorData();
        data.setID(tpsID);
        data.setHost(cs.getString("tps." + tpsID + ".host", ""));
        data.setPort(cs.getString("tps." + tpsID + ".port", ""));
        data.setUserID(cs.getString("tps." + tpsID + ".userid", ""));
        data.setNickname(cs.getString("tps." + tpsID + ".nickname", ""));
        URI uri = uriInfo.getBaseUriBuilder().path(TPSCertResource.class).path("{id}").build(tpsID);
        data.setLink(new Link("self", uri));
        return data;
    }

    @Override
    public TPSConnectorData getConnector(String id) {

        if (id == null) throw new BadRequestException("TPS connector ID is null.");

        try {
            if (connectorExists(id)) return createTPSConnectorData(id);
            throw new ResourceNotFoundException("Connector " + id + " not found.");
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Unable to get TPS connection data" + e);
        }
    }

    @Override
    public TPSConnectorData getConnector(String host, String port) {

        if (host == null) throw new BadRequestException("TPS connector host is null.");
        if (port == null) throw new BadRequestException("TPS connector port is null.");

        try {
            String id = getConnectorID(host, port);
            if (id != null) return createTPSConnectorData(id);
            throw new ResourceNotFoundException(
                    "Connector not found for " + host + ":" + port);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Unable to get TPS connection data" + e);
        }
    }

    @Override
    public Response createConnector(String tpsHost, String tpsPort) {

        if (tpsHost == null) throw new BadRequestException("TPS connector host is null.");
        if (tpsPort == null) throw new BadRequestException("TPS connector port is null.");

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

            return Response
                    .created(newData.getLink().getHref())
                    .entity(newData)
                    .type(MediaType.APPLICATION_XML)
                    .build();

        } catch (EBaseException e) {
            CMS.debug("Unable to create new TPS Connector: " + e);
            e.printStackTrace();
            throw new PKIException("Unable to create  new TPS connector: " + e);
        }
    }

    @Override
    public Response modifyConnector(String id, TPSConnectorData data) {
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
            cs.commit(true);

            return Response
                    .ok(curData.getLink().getHref())
                    .entity(curData)
                    .type(MediaType.APPLICATION_XML)
                    .build();
        } catch (EBaseException e) {
            CMS.debug("Unable to modify TPS Connector: " + e);
            e.printStackTrace();
            throw new PKIException("Unable to modify TPS Connector: " + e);
        }
    }

    private void saveClientData(TPSConnectorData newData) throws EBaseException {
        String id = newData.getID();
        if (StringUtils.isEmpty(id)) {
            CMS.debug("saveClientData: Attempt to save tps connection with null or empty id");
            return;
        }
        String prefix = "tps." + id + ".";

        if (newData.getHost() != null)
            cs.putString(prefix + "host", newData.getHost());
        if (newData.getPort() != null)
            cs.putString(prefix + "port", newData.getPort());
        if (newData.getUserID() != null)
            cs.putString(prefix + "userid", newData.getUserID());
        if (newData.getNickname() != null)
            cs.putString(prefix + "nickname", newData.getNickname());
    }

    @Override
    public void deleteConnector(String id) {
        try {
            if (StringUtils.isEmpty(id))
                throw new BadRequestException("Attempt to delete TPS connection with null or empty id");

            if (!connectorExists(id)) return;

            deleteSharedSecret(id);
            cs.removeSubStore("tps." + id);
            removeFromConnectorList(id);
            cs.commit(true);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Failed to delete TPS connection" + e);
        }
    }

    @Override
    public void deleteConnector(String host, String port) {

        if (host == null) throw new BadRequestException("TPS connector host is null.");
        if (port == null) throw new BadRequestException("TPS connector port is null.");

        String id;
        try {
            id = getConnectorID(host, port);
            deleteConnector(id);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Failed to delete TPS connector: " + e);
        }
    }

    @Override
    public KeyData createSharedSecret(String id) {

        if (id == null) throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(id);

            // get user cert
            IUser user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            String nickname = userid + " sharedSecret";
            if (CryptoUtil.sharedSecretExists(nickname)) {
                throw new BadRequestException("Shared secret already exists");
            }

            CryptoUtil.createSharedSecret(nickname);

            cs.putString("tps." + id + ".nickname", nickname);
            cs.commit(true);

            byte[] wrappedKey = CryptoUtil.exportSharedSecret(nickname, certs[0]);
            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encode(wrappedKey));
            return keyData;

        } catch (InvalidKeyException | IllegalStateException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | EBaseException
                | NotInitializedException | TokenException | IOException | InvalidKeyFormatException e) {
            e.printStackTrace();
            CMS.debug("Error in generating and exporting shared secret: " + e);
            throw new PKIException("Error in generating and exporting shared secret: " + e);
        }
    }

    private String validateUser(String id) throws EBaseException {
        String userid = cs.getString("tps." + id + ".userid", "");
        if (userid.isEmpty()) {
            throw new PKIException("Bad TPS connection configuration: userid not defined");
        }

        PKIPrincipal principal = (PKIPrincipal) servletRequest.getUserPrincipal();
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
    public KeyData replaceSharedSecret(String id) {

        if (id == null) throw new BadRequestException("TPS connector ID is null.");

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
            IUser user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            CryptoUtil.deleteSharedSecret(nickname);
            CryptoUtil.createSharedSecret(nickname);
            byte[] wrappedKey = CryptoUtil.exportSharedSecret(nickname, certs[0]);
            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encode(wrappedKey));
            return keyData;
        } catch (InvalidKeyException | IllegalStateException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | EBaseException
                | NotInitializedException | TokenException | IOException | InvalidKeyFormatException e) {
            e.printStackTrace();
            CMS.debug("Error in replacing shared secret: " + e);
            throw new PKIException("Error in replacing shared secret: " + e);
        }
    }

    @Override
    public void deleteSharedSecret(String id) {

        if (id == null) throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get user
            String userid = cs.getString("tps." + id + ".userid", "");
            if (userid.isEmpty()) {
                throw new PKIException("Bad TPS connection configuration: userid not defined");
            }

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return;
            }
            CryptoUtil.deleteSharedSecret(nickname);

            cs.putString("tps." + id + ".nickname", "");
            cs.commit(true);
        } catch (InvalidKeyException | IllegalStateException | EBaseException
                | NotInitializedException | TokenException e) {
            e.printStackTrace();
            CMS.debug("Error in deleting shared secret: " + e);
            throw new PKIException("Error in deleting shared secret: " + e);
        }
    }

    @Override
    public KeyData getSharedSecret(String id) {

        if (id == null) throw new BadRequestException("TPS connector ID is null.");

        try {
            if (!connectorExists(id)) {
                throw new ResourceNotFoundException("TPS connection does not exist");
            }

            // get and validate user
            String userid = validateUser(id);

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return null;
            }

            // get user cert
            IUser user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            byte[] wrappedKey = CryptoUtil.exportSharedSecret(nickname, certs[0]);
            KeyData keyData = new KeyData();
            keyData.setWrappedPrivateData(Utils.base64encode(wrappedKey));
            return keyData;
        } catch (InvalidKeyException | IllegalStateException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | EBaseException
                | NotInitializedException | TokenException | IOException | InvalidKeyFormatException e) {
            e.printStackTrace();
            CMS.debug("Error in obtaining shared secret: " + e);
            throw new PKIException("Error in obtaining shared secret: " + e);
        }
    }

    private boolean connectorExists(String id) throws EBaseException {
        String tpsList = cs.getString(TPS_LIST, "");
        return ArrayUtils.contains(StringUtils.split(tpsList, ","), id);
    }

    private String getConnectorID(String host, String port) throws EBaseException {
        String tpsList = cs.getString(TPS_LIST, "");
        for (String tpsID : StringUtils.split(tpsList,",")) {
            TPSConnectorData data = createTPSConnectorData(tpsID);
            if (data.getHost().equals(host) && data.getPort().equals(port))
                return tpsID;
        }
        return null;
    }

    private void addToConnectorList(String id) throws EBaseException {
        String tpsList = cs.getString(TPS_LIST, "");
        Collection<String> sorted = new TreeSet<String>();
        sorted.addAll(Arrays.asList(StringUtils.split(tpsList, ",")));
        sorted.add(id);
        cs.putString(TPS_LIST, StringUtils.join(sorted, ","));
    }

    private void removeFromConnectorList(String id) throws EBaseException {
        String tpsList = cs.getString(TPS_LIST, "");
        Collection<String> sorted = new TreeSet<String>();
        sorted.addAll(Arrays.asList(StringUtils.split(tpsList, ",")));
        sorted.remove(id);
        cs.putString(TPS_LIST, StringUtils.join(sorted, ","));
    }

    private String findNextConnectorID() throws EBaseException {
        String tpsList = cs.getString(TPS_LIST, "");
        Collection<String> sorted = new TreeSet<String>();
        sorted.addAll(Arrays.asList(StringUtils.split(tpsList, ",")));

        int index = 0;
        while (sorted.contains(Integer.toString(index))) index++;
        return Integer.toString(index);
    }
}
