/*
 * Copyright 2024-2026 Netcracker Technology Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jayway;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Map;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.minidev.json.parser.JSONParser;

/**
 * Evaluates jsonPath cases with Jayway JsonPath in its default configuration,
 * over a document Jackson reads with every number that has a fraction or an
 * exponent as a BigDecimal. A document read that way gives the answer the
 * legacy service gives for a number beyond the double range, where a document
 * json-smart reads makes Jayway throw.
 */
public final class Run {
    private Run() {
    }

    /**
     * Reads a JSON array of cases, each {"id", "doc", "path"}, from the file
     * named by the first argument, and prints one JSON line per case:
     * {"id", "value"} for a result, {"id", "compileError", "message"} where
     * the path does not compile, or {"id", "error", "message"} for an
     * exception while the path is read. A double that JSON cannot hold
     * prints as {"double": "Infinity"}, and so on.
     *
     * @param args the file of cases
     * @throws Exception if the file cannot be read or parsed
     */
    public static void main(final String[] args) throws Exception {
        JSONArray cases = (JSONArray) new JSONParser(JSONParser.MODE_PERMISSIVE)
                .parse(Files.readString(Path.of(args[0])));
        Configuration conf = Configuration.defaultConfiguration();
        ObjectMapper mapper = new ObjectMapper()
                .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
        StringBuilder out = new StringBuilder();
        for (Object o : cases) {
            JSONObject c = (JSONObject) o;
            out.append("{\"id\":").append(JSONValue.toJSONString(c.get("id")));
            JsonPath path = null;
            try {
                path = JsonPath.compile((String) c.get("path"));
            } catch (Throwable e) {
                fail(out, "compileError", e);
            }
            if (path != null) {
                try {
                    String text = (String) c.get("doc");
                    Object doc = mapper.readValue(text, Object.class);
                    Object value = path.read(doc, conf);
                    out.append(",\"value\":");
                    write(out, value);
                } catch (Throwable e) {
                    fail(out, "error", e);
                }
            }
            out.append("}\n");
        }
        System.out.print(out);
    }

    private static void fail(final StringBuilder out, final String field,
            final Throwable e) {
        out.append(",\"").append(field).append("\":").append(
                JSONValue.toJSONString(e.getClass().getSimpleName()));
        out.append(",\"message\":").append(
                JSONValue.toJSONString(String.valueOf(e.getMessage())));
    }

    private static void write(final StringBuilder out, final Object v) {
        if (v == null) {
            out.append("null");
        } else if (v instanceof Double d && (d.isInfinite() || d.isNaN())) {
            out.append("{\"double\":\"").append(d).append("\"}");
        } else if (v instanceof Number || v instanceof Boolean) {
            out.append(v);
        } else if (v instanceof String s) {
            out.append(JSONValue.toJSONString(s));
        } else if (v instanceof Map<?, ?> m) {
            out.append('{');
            String sep = "";
            for (Map.Entry<?, ?> e : m.entrySet()) {
                String key = String.valueOf(e.getKey());
                out.append(sep).append(JSONValue.toJSONString(key)).append(':');
                write(out, e.getValue());
                sep = ",";
            }
            out.append('}');
        } else if (v instanceof Collection<?> list) {
            out.append('[');
            String sep = "";
            for (Object e : list) {
                out.append(sep);
                write(out, e);
                sep = ",";
            }
            out.append(']');
        } else {
            out.append("{\"class\":")
                    .append(JSONValue.toJSONString(v.getClass().getName()))
                    .append('}');
        }
    }
}
