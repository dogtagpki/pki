package com.netscape.certsrv.util;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.node.TextNode;

public class StringHashMapValueDeserializer extends JsonDeserializer<HashMap<String, String>> {

    @Override
    public HashMap<String, String> deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException {
        HashMap<String, String> ret = new HashMap<>();
        TreeNode node = parser.getCodec().readTree(parser);
        if (node != null && node.isArray()) {
            // If node is an array take the first element, if already map-like use it directly.
            node = node.get(0);
        }
        if (node != null) {
            for (Iterator<String> iter = node.fieldNames(); iter.hasNext();) {
                String field = iter.next();
                TextNode valueNode = (TextNode) node.get(field);
                ret.put(field, valueNode.asText());
            }
        }
        return ret;
    }
}
