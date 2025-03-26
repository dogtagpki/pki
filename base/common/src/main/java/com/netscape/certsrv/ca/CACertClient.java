//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertDataInfos;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class CACertClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(CACertClient.class);

    public CACertRequestClient certRequestClient;
    public CAAgentCertClient agentCertClient;
    public CAAgentCertRequestClient agentCertRequestClient;

    public CACertClient(SubsystemClient subsystemClient) throws Exception {
        this(subsystemClient.client, subsystemClient.getName());
    }

    public CACertClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "certs");
        init();
    }

    public void init() throws Exception {
        certRequestClient = new CACertRequestClient(client);
        agentCertClient = new CAAgentCertClient(client);
        agentCertRequestClient = new CAAgentCertRequestClient(client);
    }

    public CertData getCert(CertId id) throws Exception {
        return get(id.toHexString(), CertData.class);
    }

    public CertData reviewCert(CertId id) throws Exception {
        return agentCertClient.reviewCert(id);
    }

    public CertDataInfos listCerts(String status, Integer maxResults, Integer maxTime, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (status != null) params.put("status", status);
        if (maxResults != null) params.put("maxResults", maxResults);
        if (maxTime != null) params.put("maxTime", maxTime);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, CertDataInfos.class);
    }

    public CertDataInfos findCerts(CertSearchRequest data, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        String searchRequest = (String) client.marshall(data);
        Entity<String> entity = client.entity(searchRequest);
        return post("search", params, entity, CertDataInfos.class);
    }

    public CertRequestInfo revokeCert(CertId id, CertRevokeRequest request) throws Exception {
        return agentCertClient.revokeCert(id, request);
    }

    public CertRequestInfo revokeCACert(CertId id, CertRevokeRequest request) throws Exception {
        return agentCertClient.revokeCACert(id, request);
    }

    public CertRequestInfo unrevokeCert(CertId id) throws Exception {
        return agentCertClient.unrevokeCert(id);
    }

    public CertRequestInfos enrollRequest(
            CertEnrollmentRequest data, AuthorityID aid, X500Name adn) throws Exception {
        return certRequestClient.enrollRequest(data, aid, adn);
    }

    public CertRequestInfo getRequest(RequestId id) throws Exception {
        return certRequestClient.getRequest(id);
    }

    public CertReviewResponse reviewRequest(RequestId id) throws Exception {
        return agentCertRequestClient.reviewRequest(id);
    }

    public void approveRequest(RequestId id, CertReviewResponse data) throws Exception {
        agentCertRequestClient.approveRequest(id, data);
    }

    public void rejectRequest(RequestId id, CertReviewResponse data) throws Exception {
        agentCertRequestClient.rejectRequest(id, data);
    }

    public void cancelRequest(RequestId id, CertReviewResponse data) throws Exception {
        agentCertRequestClient.cancelRequest(id, data);
    }

    public void updateRequest(RequestId id, CertReviewResponse data) throws Exception {
        agentCertRequestClient.updateRequest(id, data);
    }

    public void validateRequest(RequestId id, CertReviewResponse data) throws Exception {
        agentCertRequestClient.validateRequest(id, data);
    }

    public void assignRequest(RequestId id, CertReviewResponse data) throws Exception {
        agentCertRequestClient.assignRequest(id, data);
    }

    public void unassignRequest(RequestId id, CertReviewResponse data) throws Exception {
        agentCertRequestClient.unassignRequest(id, data);
    }

    public CertRequestInfos listRequests(String requestState, String requestType, String start, Integer pageSize,
            Integer maxResults, Integer maxTime) throws Exception {
        return agentCertRequestClient.listRequests(requestState, requestType, start, pageSize, maxResults, maxTime);
    }

    public CertEnrollmentRequest getEnrollmentTemplate(String id) throws Exception {
        return certRequestClient.getEnrollmentTemplate(id);
    }

    public ProfileDataInfos listEnrollmentTemplates(Integer start, Integer size) throws Exception {
        return certRequestClient.listEnrollmentTemplates(start, size);
    }

    public X509CertImpl submitRequest(
            String certRequestType,
            String certRequest,
            boolean renewal,
            String profileID,
            String subjectDN,
            String[] dnsNames,
            String username,
            String requestor,
            String sessionID) throws Exception {

        MultivaluedMap<String, String> content = new MultivaluedHashMap<>();
        content.putSingle("cert_request_type", certRequestType);
        content.putSingle("cert_request", certRequest);
        content.putSingle("renewal", String.valueOf(renewal));
        content.putSingle("xmlOutput", "true");
        content.putSingle("profileId", profileID);
        content.putSingle("sessionID", sessionID);

        if (subjectDN != null) {
            content.putSingle("subject", subjectDN);
        }

        if (dnsNames != null) {
            // Dynamically apply the SubjectAlternativeName extension to a
            // remote PKI instance's request for its SSL Server Certificate.
            //
            // Since this information may vary from instance to
            // instance, obtain the necessary information from the
            // 'service.sslserver.san' value(s) in the instance's
            // CS.cfg, process these values converting each item into
            // its individual SubjectAlternativeName components, and
            // build an SSL Server Certificate URL extension consisting
            // of this information.
            //
            // 03/27/2013 - Should consider removing this
            //              "buildSANSSLserverURLExtension()"
            //              method if it becomes possible to
            //              embed a certificate extension into
            //              a PKCS #10 certificate request.
            //
            int i = 0;
            for (String dnsName : dnsNames) {
                content.putSingle("req_san_pattern_" + i, dnsName);
                i++;
            }
            content.putSingle("req_san_entries", "" + i);
        }

        if (username != null) {
            content.putSingle("uid", username);
        }

        if (requestor != null) {
            content.putSingle("requestor_name", requestor);
        }

        String response = client.post("ca/ee/ca/profileSubmit", content, String.class);
        logger.debug("CACertClient: Response: " + response);

        if (response == null) {
            logger.error("No response");
            throw new IOException("No response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("CACertClient: - status: " + status);

        if (status.equals("2")) {
            logger.error("Authentication failure");
            throw new EAuthException("Authentication failure");
        }

        if (!status.equals("0")) {
            String error = parser.getValue("Error");
            logger.error("Unable to generate certificate: " + error);
            throw new IOException("Unable to generate certificate: " + error);
        }

        RequestId requestID = new RequestId(parser.getValue("Id"));
        logger.debug("CACertClient: - request ID: " + requestID.toHexString());

        String serial = parser.getValue("serialno");
        logger.debug("CACertClient: - serial: " + serial);

        String b64 = parser.getValue("b64");
        logger.debug("CACertClient: - cert: " + b64);

        b64 = CryptoUtil.stripCertBrackets(b64.trim());
        byte[] bytes = CryptoUtil.base64Decode(b64);
        return new X509CertImpl(bytes);
    }
}
