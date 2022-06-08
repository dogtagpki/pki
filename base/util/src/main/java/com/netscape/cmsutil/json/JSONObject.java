//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmsutil.json;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class JSONObject extends ObjectMapper {

    private static final long serialVersionUID = 2L;
    private static ObjectMapper mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .deactivateDefaultTyping()
            .setAnnotationIntrospector(new JacksonAnnotationIntrospector());
    private ObjectNode rootNode = null;
    private transient JsonNode jsonNode = null;

    public JSONObject() {
        rootNode = mapper.createObjectNode();
    }

    public JSONObject(InputStream s) throws IOException {
        this();
        jsonNode = mapper.readTree(s);
    }

    public ObjectMapper getMapper() {
        return mapper;
    }

    public ObjectNode getRootNode() {
        return rootNode;
    }

    protected void setRootNode(ObjectNode rootNode) {
        this.rootNode = rootNode;
    }

    public JsonNode getJsonNode() {
        return jsonNode;
    }

    protected void setJsonNode(JsonNode jsonNode) {
        this.jsonNode = jsonNode;
    }

    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        JsonFactory jfactory = new JsonFactory();
        try (JsonGenerator jGenerator = jfactory.createGenerator(stream, JsonEncoding.UTF8)) {
            jGenerator.setCodec(getMapper());
            jGenerator.writeTree(getRootNode());
        }
        return stream.toByteArray();
    }

    @Override
    public int hashCode() {
        return Objects.hash(rootNode, jsonNode);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        JSONObject other = (JSONObject) obj;
        return Objects.equals(rootNode, other.rootNode) &&
                Objects.equals(jsonNode, other.jsonNode);
    }

    @Override
    public String toString() {
        return "JSONObject [mapper=" + mapper +
                ", rootNode=" + rootNode +
                ", jsonNode=" + jsonNode +
                ", getMapper()=" + getMapper() +
                ", getRootNode()=" + getRootNode() +
                ", getJsonNode()=" + getJsonNode() +
                ", hashCode()=" + hashCode() + "]";
    }

}
