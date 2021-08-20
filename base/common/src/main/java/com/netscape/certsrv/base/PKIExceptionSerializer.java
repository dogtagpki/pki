package com.netscape.certsrv.base;

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.netscape.certsrv.base.PKIException.Data;

public class PKIExceptionSerializer extends StdSerializer<Data> {

    public PKIExceptionSerializer() {
        this(null);
    }

    public PKIExceptionSerializer(Class<Data> t) {
        super(t);
    }

    @Override
    public void serialize(
            Data data,
            JsonGenerator generator,
            SerializerProvider provider
            ) throws IOException, JsonProcessingException {

        generator.writeStartObject();

        generator.writeObjectFieldStart("Attributes");
        generator.writeArrayFieldStart("Attribute");
        for (Map.Entry<String,String> entry : data.attributes.entrySet()) {
            generator.writeStartObject();
            generator.writeStringField("name", entry.getKey());
            generator.writeStringField("value", entry.getValue());
            generator.writeEndObject();
        }
        generator.writeEndArray();
        generator.writeEndObject();

        generator.writeStringField("ClassName", data.className);
        generator.writeNumberField("Code", data.code);
        generator.writeStringField("Message", data.message);

        generator.writeEndObject();
    }
}
