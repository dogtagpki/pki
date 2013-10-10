package com.netscape.cms.servlet.processors;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.ws.rs.FormParam;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.logging.IAuditor;
import com.netscape.certsrv.logging.ILogger;

public class Processor {

    protected ILogger logger = CMS.getLogger();
    protected IAuditor auditor = CMS.getAuditor();

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

    public void audit(String message, String scope, String type, String id, Map<String, String> params, String status) {

        if (auditor == null) return;

        String auditMessage = CMS.getLogMessage(
                message,
                auditor.getSubjectID(),
                status,
                auditor.getParamString(scope, type, id, params));

        auditor.log(auditMessage);
    }

    public void log(int source, int level, String message) {

        if (logger == null) return;

        logger.log(ILogger.EV_SYSTEM,
                null,
                source,
                level,
                getClass().getSimpleName() + ": " + message);
    }
}
