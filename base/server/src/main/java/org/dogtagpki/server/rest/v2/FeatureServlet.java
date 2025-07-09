//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.WebAction;
import com.netscape.certsrv.system.Feature;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
public class FeatureServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(FeatureServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void listFeatures(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("FeatureServlet.listFeatures(): session: {}", session.getId());

        CMSEngine engine = getEngine();
        EngineConfig config = engine.getConfig();

        ConfigStore cs = config.getSubStore("features", ConfigStore.class);
        ArrayList<Feature> features = new ArrayList<>();
        Enumeration<String> tags = cs.getSubStoreNames().elements();
        while (tags.hasMoreElements()) {
            String tag = tags.nextElement();
            Feature feature = createFeature(cs, tag);
            features.add(feature);
        }
        ObjectMapper mapper = new ObjectMapper();
        PrintWriter out = response.getWriter();
        out.println(mapper.writeValueAsString(features));
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getFeature(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("FeatureServlet.getFeature(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String featureId = pathElement[0];

        CMSEngine engine = getEngine();
        EngineConfig config = engine.getConfig();
        ConfigStore cs = config.getSubStore("features", ConfigStore.class);
        Enumeration<String> tags = cs.getSubStoreNames().elements();
        while(tags.hasMoreElements()) {
            String tag = tags.nextElement();
            if (tag.equals(featureId)) {
                Feature feature = createFeature(cs, tag);
                PrintWriter out = response.getWriter();
                out.println(feature.toJSON());
                return;
            }
        }
        throw new ResourceNotFoundException("Feature " + featureId + " not supported");
    }

    private Feature createFeature(ConfigStore cs, String tag) {
        Map<String, String> props = cs.getSubStore(tag).getProperties();
        Feature feature = new Feature();
        feature.setId(tag);
        feature.setEnabled(Boolean.parseBoolean(props.get("enabled")));
        feature.setDescription(props.get("description"));
        feature.setVersion(props.get("version"));
        return feature;
    }
}
