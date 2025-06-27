//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.common.Info;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmscore.apps.CMS;

public class PKIEngine {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIEngine.class);

    public static final Path bannerFile = Paths.get(CMS.getInstanceDir(), "conf", "banner.txt");

    public static boolean isBannerEnabled() {
        return Files.exists(bannerFile);
    }

    public static String getBanner() throws IOException {
        return new String(Files.readAllBytes(bannerFile), "UTF-8").trim();
    }

    public Info getInfo(HttpServletRequest request) throws Exception {

        logger.info("PKIEngine: Getting server info");

        HttpSession session = request.getSession();
        logger.info("PKIEngine: - session: " + session.getId());

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
                logger.error("PKIEngine: Invalid access banner: " + e.getMessage(), e);
                throw new PKIException("Invalid access banner: " + e.getMessage(), e);
            }
        }

        // add other info attributes after banner validation

        String productName = CMS.getProductName();
        logger.info("PKIEngine: - product name: " + productName);
        info.setName(productName);

        String productVersion = CMS.getProductVersion();
        logger.info("PKIEngine: - product version: " + productName);
        info.setVersion(productVersion);

        return info;
    }
}
