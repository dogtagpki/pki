package com.netscape.certsrv.request;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class RequestStatusSerializer extends StdSerializer<RequestStatus> {

    public RequestStatusSerializer() {
        this(null);
    }

    public RequestStatusSerializer(Class<RequestStatus> t) {
        super(t);
    }

    @Override
    public void serialize(
            RequestStatus requestStatus,
            JsonGenerator generator,
            SerializerProvider provider
            ) throws IOException, JsonProcessingException {

        generator.writeString(requestStatus.toString());
    }
}
