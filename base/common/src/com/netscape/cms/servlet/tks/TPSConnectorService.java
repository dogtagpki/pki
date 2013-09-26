package com.netscape.cms.servlet.tks;

import java.io.IOException;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;

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
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.key.KeyData;
import com.netscape.certsrv.system.TPSConnectorCollection;
import com.netscape.certsrv.system.TPSConnectorData;
import com.netscape.certsrv.system.TPSConnectorResource;
import com.netscape.certsrv.tps.cert.TPSCertResource;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cmscore.realm.PKIPrincipal;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

public class TPSConnectorService implements TPSConnectorResource {

    IConfigStore cs = CMS.getConfigStore();

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpServletRequest servletRequest;

    public IUGSubsystem userGroupManager = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);

    @Override
    public TPSConnectorCollection listConnectors() {
        try {
            String tpsList = cs.getString("tps.list", "");
            if (tpsList.isEmpty()) {
                return null;
            }

            TPSConnectorCollection ret = new TPSConnectorCollection();
            for (String tpsID : tpsList.split(",")) {
                ret.addEntry(createTPSSystemClientData(tpsID));
            }
            return ret;
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Unable to get TPS connection data" + e);
        }
    }

    private TPSConnectorData createTPSSystemClientData(String tpsID) throws EBaseException {
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
        try {
            String tpsList = cs.getString("tps.list", "");
            if (tpsList.isEmpty()) {
                return null;
            }

            for (String tpsID : tpsList.split(",")) {
                if (tpsID.equals(id))
                    return createTPSSystemClientData(tpsID);
            }
            return null;
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Unable to get TPS connection data" + e);
        }
    }

    @Override
    public TPSConnectorData getConnector(String host, String port) {
        try {
            String tpsList = cs.getString("tps.list", "");
            if (tpsList.isEmpty()) {
                return null;
            }

            for (String tpsID : tpsList.split(",")) {
                TPSConnectorData data = createTPSSystemClientData(tpsID);
                if (data.getHost().equals(host) && data.getPort().equals(port))
                    return data;
            }
            return null;
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Unable to get TPS connection data" + e);
        }
    }

    @Override
    public TPSConnectorData createConnector(String tpsHost, String tpsPort) {
        TPSConnectorData newData = new TPSConnectorData();
        newData.setHost(tpsHost);
        newData.setPort(tpsPort);
        newData.setUserID("TPS-" + tpsHost + "-" + tpsPort);
        try {
            int index = 0;
            boolean indexFound = false;
            String tpsList = cs.getString("tps.list", "");
            if (!tpsList.isEmpty()) {
                List<String> sorted = new ArrayList<String>(Arrays.asList(tpsList.split(",")));
                Collections.sort(sorted);
                for (String tpsID : sorted) {
                    TPSConnectorData data = createTPSSystemClientData(tpsID);
                    if (data.equals(newData)) {
                        throw new BadRequestException("TPS connection already exists at " + data.getLink());
                    }
                    if (!indexFound && tpsID.equals(index)) {
                        index++;
                    } else {
                        indexFound = true;
                    }
                }
            }
            String newID = Integer.toString(index);
            newData.setID(newID);
            URI uri = uriInfo.getBaseUriBuilder().path(TPSCertResource.class).path("{id}").build(newID);
            newData.setLink(new Link("self", uri));
            saveClientData(newData);

            cs.putString("tps.list", tpsList.isEmpty() ? Integer.toString(index) :
                    tpsList + "," + index);
            cs.commit(false);

            return newData;
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Unable to create  new TPS connection data" + e);
        }
    }

    private void saveClientData(TPSConnectorData newData) throws EBaseException {
        String id = newData.getID();
        if ((id == null) || (id.isEmpty())) {
            CMS.debug("saveClientData: Attempt to save tps connection with null or empty id");
            return;
            // throw exception here?
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

        cs.commit(false);
    }

    @Override
    public void deleteConnector(String id) {
        try {
            if ((id == null) || id.isEmpty())
                throw new BadRequestException("Attempt to delete TPS connection with null or empty id");

            if (getConnector(id) == null) {
                return;
                // return 404 here?
            }

            deleteSharedSecret(id);

            String prefix = "tps." + id;
            cs.removeSubStore(prefix);

            String tpsList = cs.getString("tps.list", "");
            if (tpsList.isEmpty()) {
                return;
            }

            List<String> newList = new ArrayList<String>();
            for (String tpsID : tpsList.split(",")) {
                if (!tpsID.equals(id)) {
                    newList.add(tpsID);
                }
            }
            cs.putString("tps.list", StringUtils.join(newList, ","));
            cs.commit(false);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Failed to delete TPS connection" + e);
        }
    }

    @Override
    public KeyData createSharedSecret(String id) {
        try {
            if (getConnector(id) == null) {
                throw new BadRequestException("TPS Connection does not exist");
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
            cs.commit(false);

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
        try {
            if (getConnector(id) == null) {
                throw new BadRequestException("TPS Connection does not exist");
            }

            // get and validate user
            String userid = validateUser(id);

            // get user cert
            IUser user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                throw new BadRequestException("Cannot replace. Shared secret does not exist");
            }

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
        try {
            if (getConnector(id) == null) {
                return;
            }

            // get and validate user
            String userid = validateUser(id);

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return;
            }
            CryptoUtil.deleteSharedSecret(nickname);

            cs.putString("tps." + id + ".nickname", "");
            cs.commit(false);
        } catch (InvalidKeyException | IllegalStateException | EBaseException
                | NotInitializedException | TokenException e) {
            e.printStackTrace();
            CMS.debug("Error in deleting shared secret: " + e);
            throw new PKIException("Error in deleting shared secret: " + e);
        }
    }

    @Override
    public KeyData getSharedSecret(String id) {
        try {
            if (getConnector(id) == null) {
                throw new BadRequestException("TPS Connection does not exist");
            }

            // get and validate user
            String userid = validateUser(id);

            // get user cert
            IUser user = userGroupManager.getUser(userid);
            X509Certificate[] certs = user.getX509Certificates();

            String nickname = userid + " sharedSecret";
            if (!CryptoUtil.sharedSecretExists(nickname)) {
                return null;
            }
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

    @Override
    public void deleteConnector(String host, String port) {
        TPSConnectorData data = getConnector(host, port);
        if (data == null) {
            return;
        }
        deleteConnector(data.getID());
    }
}
