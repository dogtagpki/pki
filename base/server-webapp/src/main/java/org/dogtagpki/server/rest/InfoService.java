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

import org.dogtagpki.common.Info;
import org.dogtagpki.common.InfoResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.CMS;

/**
 * @author Endi S. Dewata
 */
public class InfoService extends PKIService implements InfoResource {

    private static Logger logger = LoggerFactory.getLogger(InfoService.class);

    @Override
    public Response getInfo() throws Exception {

        HttpSession session = servletRequest.getSession();
        logger.debug("InfoService.getInfo(): session: " + session.getId());

        Info info = new Info();

        boolean bannerDisplayed = session.getAttribute("bannerDisplayed") != null;
        boolean bannerEnabled = isBannerEnabled();

        // if banner not yet displayed in this session and it's enabled, return banner
        if (!bannerDisplayed && bannerEnabled) {

            String banner = getBanner();
            info.setBanner(banner);

            // validate banner
            try {
                // converting Info object into JSON
                String jsonInfo = info.toJSON();

                // and parse it back into Info object
                info = JSONSerializer.fromJSON(jsonInfo, Info.class);

            } catch (Exception e) {
                logger.error("InfoService: Invalid access banner: " + e.getMessage(), e);
                throw new PKIException("Invalid access banner: " + e.getMessage(), e);
            }
        }

        // add other info attributes after banner validation

        info.setName(CMS.getProductName());
        info.setVersion(CMS.getProductVersion());

        return createOKResponse(info);
    }
}
