package com.netscape.cms.servlet.processors;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.ws.rs.FormParam;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogSource;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.logging.Auditor;

public class Processor {

    protected static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    protected Logger systemLogger = Logger.getLogger();
    protected Auditor auditor = Auditor.getAuditor();

    protected String id;
    protected Locale locale;

    public Processor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        this.id = id;
        this.locale = locale;
    }

    public String getUserMessage(String messageId, String... params) {
        return CMS.getUserMessage(locale, messageId, params);
    }

    /**
     * Get the values of the fields annotated with @FormParam.
     */
    public Map<String, String> getParams(Object object) {

        Map<String, String> map = new HashMap<String, String>();

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
                e.printStackTrace();
            }
        }

        return map;
    }

    public void log(LogSource source, int level, String message) {

        if (systemLogger == null) return;

        systemLogger.log(ILogger.EV_SYSTEM,
                source,
                level,
                getClass().getSimpleName() + ": " + message);
    }
}
