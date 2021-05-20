package org.dogtagpki.server.rest;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.system.Feature;
import com.netscape.certsrv.system.FeatureResource;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

public class FeatureService extends PKIService implements FeatureResource {
    IConfigStore cs;

    @Override
    public Response listFeatures() {

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig config = engine.getConfig();

        IConfigStore cs = config.getSubStore("features");
        ArrayList<Feature> features = new ArrayList<>();
        Enumeration<String> tags = cs.getSubStoreNames();
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

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig config = engine.getConfig();

        IConfigStore cs = config.getSubStore("features");
        Enumeration<String> tags = cs.getSubStoreNames();
        while(tags.hasMoreElements()) {
            String tag = tags.nextElement();
            if (tag.equals(id)) {
                Feature feature = createFeature(cs, tag);
                return createOKResponse(feature);
            }
        }

        throw new ResourceNotFoundException("Feature " + id + " not supported");
    }

    private Feature createFeature(IConfigStore cs, String tag) {
        Map<String, String> props;
        try {
            props = cs.getSubStore(tag).getProperties();
            Feature feature = new Feature();
            feature.setId(tag);
            feature.setEnabled(Boolean.parseBoolean(props.get("enabled")));
            feature.setDescription(props.get("description"));
            feature.setVersion(props.get("version"));
            return feature;
        } catch (EBaseException e) {
            throw new PKIException(e);
        }
    }
}
