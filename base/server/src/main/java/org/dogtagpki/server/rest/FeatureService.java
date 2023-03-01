package org.dogtagpki.server.rest;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.system.Feature;
import com.netscape.certsrv.system.FeatureResource;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;

public class FeatureService extends PKIService implements FeatureResource {

    @Override
    public Response listFeatures() {

        CMSEngine engine = getCMSEngine();
        EngineConfig config = engine.getConfig();

        ConfigStore cs = config.getSubStore("features", ConfigStore.class);
        ArrayList<Feature> features = new ArrayList<>();
        Enumeration<String> tags = cs.getSubStoreNames().elements();
        while (tags.hasMoreElements()) {
            String tag = tags.nextElement();
            Feature feature = createFeature(cs, tag);
            features.add(feature);
        }
        GenericEntity<List<Feature>> entity = new GenericEntity<>(features) {};
        return createOKResponse(entity);
    }

    @Override
    public Response getFeature(String id) {

        CMSEngine engine = getCMSEngine();
        EngineConfig config = engine.getConfig();

        ConfigStore cs = config.getSubStore("features", ConfigStore.class);
        Enumeration<String> tags = cs.getSubStoreNames().elements();
        while(tags.hasMoreElements()) {
            String tag = tags.nextElement();
            if (tag.equals(id)) {
                Feature feature = createFeature(cs, tag);
                return createOKResponse(feature);
            }
        }

        throw new ResourceNotFoundException("Feature " + id + " not supported");
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
