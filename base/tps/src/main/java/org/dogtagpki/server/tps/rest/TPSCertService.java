// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.rest;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.TPSCertDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.cert.TPSCertCollection;
import com.netscape.certsrv.tps.cert.TPSCertData;
import com.netscape.certsrv.tps.cert.TPSCertResource;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class TPSCertService extends PKIService implements TPSCertResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSCertService.class);

    public TPSCertService() {
        logger.debug("TPSCertService.<init>()");
    }

    public TPSCertData createCertData(TPSCertRecord certRecord) {

        TPSCertData certData = new TPSCertData();
        certData.setID(certRecord.getId());
        certData.setSerialNumber(certRecord.getSerialNumber());
        certData.setSubject(certRecord.getSubject());
        certData.setUserID(certRecord.getUserID());
        certData.setTokenID(certRecord.getTokenID());
        certData.setOrigin(certRecord.getOrigin());
        certData.setType(certRecord.getType());
        certData.setKeyType(certRecord.getKeyType());
        certData.setStatus(certRecord.getStatus());
        certData.setCreateTime(certRecord.getCreateTime());
        certData.setModifyTime(certRecord.getModifyTime());

        String certID = certRecord.getId();
        try {
            certID = URLEncoder.encode(certID, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
        return certData;
    }

    public TPSCertRecord createCertRecord(TPSCertData certData) {

        TPSCertRecord certRecord = new TPSCertRecord();
        certRecord.setId(certData.getID());
        certRecord.setSerialNumber(certData.getSerialNumber());
        certRecord.setSubject(certData.getSubject());
        certRecord.setUserID(certData.getUserID());
        certRecord.setTokenID(certData.getTokenID());
        certRecord.setOrigin(certData.getOrigin());
        certRecord.setType(certData.getType());
        certRecord.setKeyType(certData.getKeyType());
        certRecord.setStatus(certData.getStatus());
        certRecord.setCreateTime(certData.getCreateTime());
        certRecord.setModifyTime(certData.getModifyTime());

        return certRecord;
    }

    @Override
    public Response findCerts(String filter, String tokenID, Integer start, Integer size) {
        String method = "TPSCertService:findCerts: ";
        String msg = "";
        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        logger.debug("TPSCertService.findCerts(" + filter + ", " + tokenID + ", " + start + ", " + size + ")");

        if(tokenID == null) {
            if (filter == null || filter.length() < MIN_FILTER_LENGTH) {
                throw new BadRequestException("Filter is too short. Must be at least " + MIN_FILTER_LENGTH + " characters.");
            }
            return findAllCerts(filter, start, size);
        }

        Map<String, String> attributes = new HashMap<>();
        if (tokenID != null) {
            attributes.put("tokenID", tokenID);
        }

        TPSEngine engine = TPSEngine.getInstance();
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            TokenDatabase tokDatabase = subsystem.getTokenDatabase();
            TokenRecord record = tokDatabase.getRecord(tokenID);
            if (record == null) {
                msg = "Token record not found";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }
            String type = record.getType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type))
                throw new PKIException(method + "Token record restricted");

            // token was from an authorized profile
            TPSCertDatabase database = subsystem.getCertDatabase();

            Iterator<TPSCertRecord> certRecs = database.findRecords(filter, attributes).iterator();
            TPSCertCollection response = new TPSCertCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && certRecs.hasNext(); i++) certRecs.next();

            // return entries up to the page size
            for ( ; i<start+size && certRecs.hasNext(); i++) {
                response.addEntry(createCertData(certRecs.next()));
            }

            // count the total entries
            for ( ; certRecs.hasNext(); i++) certRecs.next();
            response.setTotal(i);

            return createOKResponse(response);

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    private Response findAllCerts(String filter, Integer start, Integer size) {
        String method = "TPSCertService:findAllCerts: ";
        String msg = "";
        TPSCertCollection response = new TPSCertCollection();

        logger.debug("TPSCertService.findAllCerts({}, {}, {})", filter, start, size);

        TPSEngine engine = TPSEngine.getInstance();
        try {
            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            TPSCertDatabase certDatabase = subsystem.getCertDatabase();
            Iterator<TPSCertRecord> certRecs = certDatabase.findRecords(filter).iterator();
            TokenDatabase tokenDatabase = subsystem.getTokenDatabase();
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug("{}{}", method, msg);
                throw new PKIException(method + msg);
            }
            int total = 0;
            while (certRecs.hasNext()) {
                TPSCertRecord certRecord = certRecs.next();
                String tokenID = certRecord.getTokenID();
                TokenRecord tokenRecord = null;
                try {
                    tokenRecord = tokenDatabase.getRecord(tokenID);
                } catch (Exception e) {
                    // Proceed to next token if this one doesn't exist.
                }
                if (tokenRecord != null) {
                    String type = tokenRecord.getType();
                    if (type == null || type.isEmpty() || authorizedProfiles.contains(type) || authorizedProfiles.contains(UserResource.ALL_PROFILES)) {
                        // Return entries from the start of the page up to the page size
                        if (total >= start && total < start + size) {
                            response.addEntry(createCertData(certRecord));
                        }
                        // Count all accessible records, on this page or otherwise.
                        total++;
                    }
                }
            }
            response.setTotal(total);
            return createOKResponse(response);
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response getCert(String certID) {
       String method = "TPSCertService:getCert: ";
       String msg = "";

        if (certID == null) throw new BadRequestException("Certificate ID is null.");

        logger.debug("TPSCertService.getCert(\"" + certID + "\")");

        TPSEngine engine = TPSEngine.getInstance();
        try {
            List<String> authorizedProfiles = getAuthorizedProfiles();
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug(method + msg);
                throw new PKIException(method + msg);
            }

            TPSSubsystem subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
            TPSCertDatabase database = subsystem.getCertDatabase();
            TPSCertRecord certRec = database.getRecord(certID);
            String type = certRec.getKeyType();
            if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type))
                   throw new PKIException(method + "Cert record restricted");

            return createOKResponse(createCertData(database.getRecord(certID)));

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    /*
     * returns a list of TPS profiles allowed for the current user
     */
    List<String> getAuthorizedProfiles()
           throws Exception {
        String method = "TokenService.getAuthorizedProfiles: ";

        PKIPrincipal pkiPrincipal = (PKIPrincipal) servletRequest.getUserPrincipal();
        User user = pkiPrincipal.getUser();

        return user.getTpsProfiles();
    }
}
