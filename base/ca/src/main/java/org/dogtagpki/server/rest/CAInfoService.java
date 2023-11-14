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

import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;

import org.dogtagpki.common.CAInfoResource;
import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static Logger logger = LoggerFactory.getLogger(CAInfoService.class);


    @Override
    public Response getInfo() throws Exception {

        HttpSession session = servletRequest.getSession();
        logger.debug("CAInfoService.getInfo(): session: " + session.getId());

        CAEngine engine = (CAEngine) getCMSEngine();
        return createOKResponse(engine.getInfo(getLocale(headers)));
    }
}
