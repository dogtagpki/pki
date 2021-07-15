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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class JSONObject {

    private ObjectMapper mapper = null;
    private ObjectNode rootNode = null;

    public JSONObject() {
    }

    public JSONObject(InputStream s) throws IOException {
        mapper = new ObjectMapper();
        rootNode = mapper.createObjectNode();
        mapper.createParser(s);
    }

    public JSONObject(File f) {
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

    public String getValueFromRootNode(String value) {
        return getRootNode().get(value).asText();
    }

    @Override
    public int hashCode() {
        return Objects.hash(mapper, rootNode);
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
        return Objects.equals(mapper, other.mapper) && Objects.equals(rootNode, other.rootNode);
    }

    @Override
    public String toString() {
        return "JSONObject [mapper=" + mapper + ", rootNode=" + rootNode + ", getMapper()=" + getMapper()
                + ", getRootNode()=" + getRootNode() + ", hashCode()=" + hashCode() + "]";
    }

}
