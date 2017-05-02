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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.rest;

import java.net.MalformedURLException;
import java.net.URISyntaxException;

import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;

import org.dogtagpki.common.CAInfo;
import org.dogtagpki.common.CAInfoResource;
import org.dogtagpki.common.KRAInfo;
import org.dogtagpki.common.KRAInfoClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Ade Lee
 *
 * This class returns CA info, including KRA-related values the CA
 * clients may need to know (e.g. for generating a CRMF cert request
 * that will cause keys to be archived in KRA).
 *
 * The KRA-related info is read from the KRAInfoService, which is
 * queried according to the KRA Connector configuration.  After
 * the KRAInfoService has been successfully contacted, the recorded
 * KRA-related settings are regarded as authoritative.
 *
 * The KRA is contacted ONLY if the current info is NOT
 * authoritative, otherwise the currently recorded values are used.
 * This means that any change to relevant KRA configuration (which
 * should occur seldom if ever) necessitates restart of the CA
 * subsystem.
 *
 * If this is unsuccessful (e.g. if the KRA is down or the
 * connector is misconfigured) we use the default values, which
 * may be incorrect.
 */
public class CAInfoService extends PKIService implements CAInfoResource {

    private static Logger logger = LoggerFactory.getLogger(InfoService.class);

    // is the current KRA-related info authoritative?
    private static boolean kraInfoAuthoritative = false;

    // KRA-related fields (the initial values are only used if we
    // did not yet receive authoritative info from KRA)
    private static String archivalMechanism = KRAInfoService.KEYWRAP_MECHANISM;
    private static String wrappingKeySet = "0";

    @Override
    public Response getInfo() throws Exception {

        HttpSession session = servletRequest.getSession();
        logger.debug("CAInfoService.getInfo(): session: " + session.getId());

        KRAConnectorInfo connInfo = null;
        KRAConnectorProcessor processor =
            new KRAConnectorProcessor(getLocale(headers));
        try {
            connInfo = processor.getConnectorInfo();
        } catch (Exception e) {
            // connInfo remains as null
        }
        boolean kraEnabled =
            connInfo != null
            && "true".equalsIgnoreCase(connInfo.getEnable());

        CAInfo info = new CAInfo();

        if (!kraEnabled)
            return createOKResponse(info);

        if (!kraInfoAuthoritative)
            queryKRAInfo(connInfo);

        info.setArchivalMechanism(archivalMechanism);
        info.setWrappingKeySet(wrappingKeySet);

        return createOKResponse(info);
    }

    private static void queryKRAInfo(KRAConnectorInfo connInfo) {
        try {
            KRAInfo kraInfo = getKRAInfoClient(connInfo).getInfo();

            archivalMechanism = kraInfo.getArchivalMechanism();

            // request succeeded; the KRA is 10.4 or higher,
            // therefore supports key set v1
            wrappingKeySet = "1";

            // mark info as authoritative
            kraInfoAuthoritative = true;
        } catch (PKIException e) {
            if (e.getCode() == 404) {
                // The KRAInfoResource was added in 10.4,
                // so we are talking to a pre-10.4 KRA

                // pre-10.4 only supports key set v0
                wrappingKeySet = "0";

                // pre-10.4 KRA does not advertise the archival
                // mechanism; look for the old knob in CA's config
                // or fall back to the default
                IConfigStore cs = CMS.getConfigStore();
                boolean encrypt_archival;
                try {
                    encrypt_archival = cs.getBoolean(
                        "kra.allowEncDecrypt.archival", false);
                } catch (EBaseException e1) {
                    encrypt_archival = false;
                }
                archivalMechanism = encrypt_archival
                    ? KRAInfoService.ENCRYPT_MECHANISM
                    : KRAInfoService.KEYWRAP_MECHANISM;

                // mark info as authoritative
                kraInfoAuthoritative = true;
            } else {
                CMS.debug("Failed to retrieve archive wrapping information from the CA: " + e);
                CMS.debug(e);
            }
        } catch (Exception e) {
            CMS.debug("Failed to retrieve archive wrapping information from the CA: " + e);
            CMS.debug(e);
        }
    }

    /**
     * Construct KRAInfoClient given KRAConnectorInfo
     */
    private static KRAInfoClient getKRAInfoClient(KRAConnectorInfo connInfo)
            throws MalformedURLException, URISyntaxException, EBaseException {
        ClientConfig config = new ClientConfig();
        int port = Integer.parseInt(connInfo.getPort());
        config.setServerURL("https", connInfo.getHost(), port);
        config.setCertDatabase(
            CMS.getConfigStore().getString("instanceRoot") + "/alias");
        return new KRAInfoClient(new PKIClient(config), "kra");
    }

}
