// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2021 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
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

public class JSONObject {

    private ObjectMapper mapper = null;
    private ObjectNode rootNode = null;
    private JsonNode jsonNode = null;

    public JSONObject() {
        mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.setAnnotationIntrospector(new JacksonAnnotationIntrospector());
        rootNode = mapper.createObjectNode();
    }

    public JSONObject(InputStream s) throws IOException {
        this();
        jsonNode = mapper.readTree(s);
    }

    public ObjectMapper getMapper() {
        return mapper;
    }

    protected void setMapper(ObjectMapper mapper) {
        this.mapper = mapper;
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

    public String getValueFromJsonNode(String fieldName) {
        return jsonNode.get(fieldName).asText();
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
        return Objects.hash(jsonNode, mapper, rootNode);
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
        return Objects.equals(jsonNode, other.jsonNode) && Objects.equals(mapper, other.mapper)
                && Objects.equals(rootNode, other.rootNode);
    }

    @Override
    public String toString() {
        return "JSONObject [mapper=" + mapper + ", rootNode=" + rootNode + ", jsonNode=" + jsonNode + "]";
    }

}
