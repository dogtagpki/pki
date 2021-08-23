package com.netscape.certsrv.request;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

public class RequestStatusDeserializer extends StdDeserializer<RequestStatus> {

    public RequestStatusDeserializer() {
        this(null);
    }

    public RequestStatusDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public RequestStatus deserialize(
            JsonParser parser,
            DeserializationContext context
            ) throws IOException, JsonProcessingException {

        JsonNode node = parser.getCodec().readTree(parser);
        return RequestStatus.valueOf(node.asText());
    }
}
