package com.netscape.certsrv.util;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.netscape.certsrv.base.PKIException;

/**
 * Implement this interface to provide default methods to serialize an object to/from JSON
 */
public interface JSONSerializer {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JSONSerializer.class);

    default String toJSON() throws JsonProcessingException {
        return new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .deactivateDefaultTyping()
                .setAnnotationIntrospector(new JacksonAnnotationIntrospector())
                .writeValueAsString(this);
    }

    static <T> T fromJSON(String json, Class<T> clazz) throws JsonProcessingException {
        try {
            return new ObjectMapper()
                    .setAnnotationIntrospector(new JacksonAnnotationIntrospector())
                    .deactivateDefaultTyping()
                    .readValue(json, clazz);
        } catch (JsonParseException e) {
            String errMsg = "The input file provided could not be parsed as JSON";
            logger.debug(errMsg, e);
            throw new PKIException(errMsg);
        }
    }

}
