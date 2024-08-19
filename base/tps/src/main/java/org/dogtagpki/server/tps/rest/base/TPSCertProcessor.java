//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.base;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.dbs.TPSCertDatabase;
import org.dogtagpki.server.tps.dbs.TPSCertRecord;
import org.dogtagpki.server.tps.dbs.TokenDatabase;
import org.dogtagpki.server.tps.dbs.TokenRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.tps.cert.TPSCertCollection;
import com.netscape.certsrv.tps.cert.TPSCertData;
import com.netscape.certsrv.user.UserResource;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class TPSCertProcessor {
    private static final Logger logger = LoggerFactory.getLogger(TPSCertProcessor.class);
    private TPSSubsystem subsystem;


    public TPSCertProcessor(TPSEngine engine) {
        subsystem = (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
    }


    public TPSCertCollection findCerts(List<String> authorizedProfiles, String tokenID, String filter, int start, int size) {
        String method = "TPSCertProcessor:findCerts: ";
        String msg = "";
        logger.debug("TPSCertProcessor.findCerts({}, {}, {}, {})", filter, tokenID, start, size);

        if(tokenID == null) {
            //TODO: filter should not be mandatory but it is required to overcome a UI limitation
            if (filter == null || filter.length() < PKIServlet.MIN_FILTER_LENGTH) {
                throw new BadRequestException("Filter is too short. Must be at least " + PKIServlet.MIN_FILTER_LENGTH + " characters.");
            }
            return findAllCerts(authorizedProfiles, filter, start, size);
        }

        Map<String, String> attributes = new HashMap<>();
        if (tokenID != null) {
            attributes.put("tokenID", tokenID);
        }

        try {
            if (authorizedProfiles == null) {
                msg = "authorizedProfiles null";
                logger.debug("{}{}", method, msg);
                throw new PKIException(method + msg);
            }

            TokenDatabase tokDatabase = subsystem.getTokenDatabase();
            TokenRecord tRecord = tokDatabase.getRecord(tokenID);
            if (tRecord == null) {
                msg = "Token record not found";
                logger.debug("{}{}", method, msg);
                throw new PKIException(method + msg);
            }
            String type = tRecord.getType();
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

            return response;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }


    public TPSCertData getCert(String certID, List<String> authorizedProfiles) {
        String method = "TPSCertProcessor:getCert: ";
        String msg = "";

         if (certID == null) throw new BadRequestException("Certificate ID is null.");

         logger.debug("TPSCertProcessor.getCert(\"{}\")", certID);

         try {
             if (authorizedProfiles == null) {
                 msg = "authorizedProfiles null";
                 logger.debug("{}{}", method, msg);
                 throw new PKIException(method + msg);
             }

             TPSCertDatabase database = subsystem.getCertDatabase();
             TPSCertRecord certRec = database.getRecord(certID);
             String type = certRec.getKeyType();
             if ((type != null) && !type.isEmpty() && !authorizedProfiles.contains(UserResource.ALL_PROFILES) && !authorizedProfiles.contains(type))
                    throw new PKIException(method + "Cert record restricted");

             return createCertData(database.getRecord(certID));

         } catch (Exception e) {
             throw new PKIException(e.getMessage());
         }
    }

    private TPSCertData createCertData(TPSCertRecord certRecord) {
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
        return certData;
    }

    private TPSCertCollection findAllCerts(List<String> authorizedProfiles, String filter, Integer start, Integer size) {
        String method = "TPSCertProcessor:findAllCerts: ";
        String msg = "";
        TPSCertCollection response = new TPSCertCollection();

        logger.debug("TPSCertProcessor.findAllCerts({}, {}, {})", filter, start, size);

        try {
            TPSCertDatabase certDatabase = subsystem.getCertDatabase();
            Iterator<TPSCertRecord> certRecs = certDatabase.findRecords(filter).iterator();
            TokenDatabase tokenDatabase = subsystem.getTokenDatabase();
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
            return response;
        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }
}
