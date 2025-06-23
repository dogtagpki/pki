//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.ca;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class CACRLClient extends Client {

    public final static Logger logger = LoggerFactory.getLogger(CACRLClient.class);

    public CACRLClient(CAClient caClient) throws Exception {
        this(caClient.client, caClient.getName());
    }

    public CACRLClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "crls");
    }

    public void updateCRL() throws Exception {

        List<NameValuePair> content = new ArrayList<>();
        content.add(new BasicNameValuePair("xml", "true"));

        String response = client.post(
                "ca/agent/ca/updateCRL",
                content,
                String.class);
        logger.info("Response:\n" + response);

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);
        Document doc = parser.getDocument();
        Element root = doc.getDocumentElement();

        // https://github.com/dogtagpki/pki/wiki/UpdateCRL-Service
        //
        // Success:
        // <?xml version="1.0" encoding="UTF-8" standalone="no"?>
        // <xml>
        //   <header>
        //     <crlIssuingPoint>MasterCRL</crlIssuingPoint>
        //     <crlUpdate>Scheduled</crlUpdate>
        //   </header>
        //   <fixed/>
        //   <records/>
        // </xml>
        //
        // Failure:
        // <?xml version="1.0" encoding="UTF-8" standalone="no"?>
        // <xml>
        //   <header/>
        //   <fixed>
        //     <authorityName>Certificate Manager</authorityName>
        //     <unexpectedError>You did not provide a valid certificate for this operation</unexpectedError>
        //     <requestStatus>7</requestStatus>
        //   </fixed>
        //   <records/>
        // </xml>

        int status = 0;
        String errorMessage = null;

        NodeList fixedList = root.getElementsByTagName("fixed");
        if (fixedList.getLength() > 0) {
            Element fixed = (Element) fixedList.item(0);

            NodeList requestStatusList = fixed.getElementsByTagName("requestStatus");
            if (requestStatusList.getLength() > 0) {
                String value = requestStatusList.item(0).getTextContent();
                status = Integer.parseInt(value);
            }

            NodeList unexpectedErrorList = fixed.getElementsByTagName("unexpectedError");
            if (unexpectedErrorList.getLength() > 0) {
                errorMessage = unexpectedErrorList.item(0).getTextContent();
            }
        }

        logger.info("Status: " + status);
        logger.info("Error message: " + errorMessage);

        // Status is defined in CMSRequest:
        // 1 = UNAUTHORIZED
        // 2 = SUCCESS
        // 3 = PENDING
        // 4 = SVC_PENDING
        // 5 = REJECTED
        // 6 = ERROR
        // 7 = EXCEPTION

        if (status == 1 || status >= 5) {
            if (errorMessage == null) {
                errorMessage = "status=" + status;
            }
            throw new PKIException("Unable to update CRL: " + errorMessage);
        }
    }
}
