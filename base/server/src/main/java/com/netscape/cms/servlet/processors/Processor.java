package com.netscape.cms.servlet.processors;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.ws.rs.FormParam;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

public class Processor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(Processor.class);

    protected String id;
    protected Locale locale;
    protected CMSEngine engine;

    public Processor(String id, Locale locale) {
        this.id = id;
        this.locale = locale;
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    public void init() throws EPropertyNotFound, EBaseException {
    }

    public String getUserMessage(String messageId, String... params) {
        return CMS.getUserMessage(locale, messageId, params);
    }

    /**
     * Get the values of the fields annotated with @FormParam.
     */
    public Map<String, String> getParams(Object object) {

        Map<String, String> map = new HashMap<>();

        // for each fields in the object
        for (Method method : object.getClass().getMethods()) {
            FormParam element = method.getAnnotation(FormParam.class);
            if (element == null) continue;

            String name = element.value();

            try {
                // get the value from the object
                Object value = method.invoke(object);

                // put the value in the map
                map.put(name, value == null ? null : value.toString());

            } catch (Exception e) {
                // ignore inaccessible fields
                logger.warn("Processor: " + e.getMessage(), e);
            }
        }

        return map;
    }
}
