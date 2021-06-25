package org.dogtagpki.server.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * Implement this interface to provide default methods to serialize an object to/from JSON
 */
public interface JSONSerializer {

    default String toJSON() throws Exception {
        return new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(this);
    }

    static <T> T fromJSON(String json, Class<T> clazz) throws Exception {
        return new ObjectMapper().readValue(json, clazz);
    }

}
