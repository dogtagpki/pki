package com.netscape.certsrv.base;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.node.IntNode;
import com.netscape.certsrv.base.PKIException.Data;

public class PKIExceptionDeserializer extends StdDeserializer<Data> {

    public PKIExceptionDeserializer() {
        this(null);
    }

    public PKIExceptionDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public Data deserialize(
            JsonParser parser,
            DeserializationContext context
            ) throws IOException, JsonProcessingException {

        Data data = new Data();

        JsonNode node = parser.getCodec().readTree(parser);

        JsonNode attributes = node.get("Attributes");
        JsonNode attribute = attributes.get("Attribute");
        for (JsonNode attr : attribute) {
            String name = attr.get("name").asText();
            String value = attr.get("value").asText();
            data.attributes.put(name, value);
        }

        data.className = node.get("ClassName").asText();
        data.code = (Integer) ((IntNode) node.get("Code")).numberValue();
        data.message = node.get("Message").asText();

        return data;
    }
}
