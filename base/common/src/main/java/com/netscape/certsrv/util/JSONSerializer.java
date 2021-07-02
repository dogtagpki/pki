package com.netscape.certsrv.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;

/**
 * Implement this interface to provide default methods to serialize an object to/from JSON
 */
public interface JSONSerializer {

    default String toJSON() throws Exception {
        return new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .setAnnotationIntrospector(new JacksonAnnotationIntrospector())
                .writeValueAsString(this);
    }

    static <T> T fromJSON(String json, Class<T> clazz) throws Exception {
        return new ObjectMapper()
                .setAnnotationIntrospector(new JacksonAnnotationIntrospector())
                .readValue(json, clazz);
    }

}
