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

package jayway.recorder;

import static net.bytebuddy.matcher.ElementMatchers.isConstructor;
import static net.bytebuddy.matcher.ElementMatchers.isStatic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.takesArgument;
import static net.bytebuddy.matcher.ElementMatchers.takesArguments;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.Predicate;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

/**
 * Records the paths and documents that Jayway JsonPath's own tests evaluate,
 * as input for the differential test of the Go package internal/jsonpath.
 *
 * <p>Load it with {@code -javaagent:recorder.jar=<directory>}. Every JVM
 * writes one file of JSON lines into the directory, one line per call:
 * {@code {"test", "seq", "path", "doc"}} for a read of a document, and
 * {@code {"test", "seq", "path", "compileError": true}} for a path that does
 * not compile. {@code test} names the test method that made the call, as
 * {@code Class.method} with the class name relative to
 * {@code com.jayway.jsonpath}, and {@code seq} numbers the calls of that
 * method from 1. {@code doc} is the document as JSON text.
 *
 * <p>A document made of maps, lists, strings, numbers, booleans, and nulls
 * is written by {@link #toJson}; any other document, such as a Jackson or
 * Gson tree, by the {@code toJson} of the JSON provider the read is
 * configured with. A call is skipped where neither can write the document,
 * and where the path carries {@link Predicate} arguments, which a path
 * string cannot express. The agent prints the counts to standard error when
 * the JVM exits.
 *
 * <p>Only the outermost call on a thread is recorded, so a path that Jayway
 * reads or compiles while it evaluates another one is not. A compilation
 * outside a read is recorded too: a test that builds a filter with
 * {@code Criteria} makes Jayway compile each value that starts with
 * {@code $} or {@code @}, and a value that does not compile is recorded as
 * a path that does not compile.
 */
public final class Recorder {
    /**
     * The path text of each JsonPath, or null for one compiled with
     * Predicate arguments.
     */
    private static final Map<Object, String> PATHS =
            Collections.synchronizedMap(new WeakHashMap<Object, String>());
    /** The number of calls recorded for each test method. */
    private static final Map<String, AtomicInteger> SEQ =
            new ConcurrentHashMap<String, AtomicInteger>();
    /** The number of reads and compilations each thread is in. */
    private static final ThreadLocal<int[]> DEPTH = new ThreadLocal<int[]>() {
        @Override
        protected int[] initialValue() {
            return new int[1];
        }
    };
    /** The number of calls written. */
    private static final AtomicInteger RECORDED = new AtomicInteger();
    /** The number of calls skipped for their Predicate arguments. */
    private static final AtomicInteger WITH_PREDICATES = new AtomicInteger();
    /** The number of calls skipped for a document JSON cannot hold. */
    private static final AtomicInteger NOT_JSON = new AtomicInteger();
    /** The output file. */
    private static OutputStream out;
    /** The package prefix {@link #testName} drops from a class name. */
    private static final String JAYWAY_PACKAGE = "com.jayway.jsonpath.";

    private Recorder() {
    }

    /**
     * Instruments JsonPath and PathCompiler and opens the output file.
     *
     * @param args the directory to write the output file into
     * @param inst the instrumentation the JVM passes to an agent
     * @throws IOException if the directory cannot be created
     */
    public static void premain(final String args, final Instrumentation inst)
            throws IOException {
        Path dir = Paths.get(args);
        Files.createDirectories(dir);
        out = new FileOutputStream(
                dir.resolve("calls-" + UUID.randomUUID() + ".jsonl").toFile());
        Runtime.getRuntime().addShutdownHook(new Thread(() ->
                System.err.println("jsonpath recorder: " + RECORDED
                        + " calls recorded, " + WITH_PREDICATES
                        + " with Predicate arguments skipped, " + NOT_JSON
                        + " with a document JSON cannot hold skipped")));
        new AgentBuilder.Default()
                .with(AgentBuilder.Listener.StreamWriting.toSystemError()
                        .withErrorsOnly())
                .type(named("com.jayway.jsonpath.JsonPath"))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(Construct.class).on(isConstructor()
                                .and(takesArguments(String.class,
                                        Predicate[].class))))
                        .visit(Advice.to(Read.class).on(named("read")
                                .and(takesArguments(Object.class,
                                        Configuration.class)))))
                .type(named("com.jayway.jsonpath.internal.path.PathCompiler"))
                .transform((builder, type, loader, module, domain) -> builder
                        .visit(Advice.to(Compile.class).on(named("compile")
                                .and(isStatic())
                                .and(takesArgument(0, String.class)))))
                .installOn(inst);
    }

    /** Remembers the path text each JsonPath was compiled from. */
    public static final class Construct {
        private Construct() {
        }

        /**
         * Remembers the path text the new JsonPath was compiled from.
         *
         * @param self the new JsonPath
         * @param path the path text
         * @param filters the Predicate arguments
         */
        @Advice.OnMethodExit
        public static void exit(@Advice.This final Object self,
                @Advice.Argument(0) final String path,
                @Advice.Argument(1) final Predicate[] filters) {
            Recorder.compiled(self, path, filters == null ? 0 : filters.length);
        }
    }

    /** Records a read of a document. */
    public static final class Read {
        private Read() {
        }

        /**
         * Records the path and the document of an outermost read.
         *
         * @param self the JsonPath being read
         * @param json the document, in the representation of the configured
         *     JSON provider
         * @param conf the configuration of the read
         */
        @Advice.OnMethodEnter
        public static void enter(@Advice.This final Object self,
                @Advice.Argument(0) final Object json,
                @Advice.Argument(1) final Configuration conf) {
            if (Recorder.enter() != 0) {
                return;
            }
            String doc;
            try {
                doc = Recorder.toJson(json);
            } catch (RuntimeException e) {
                try {
                    doc = conf.jsonProvider().toJson(json);
                } catch (RuntimeException e2) {
                    doc = null;
                }
            }
            Recorder.read(self, doc);
        }

        /** Leaves the read. */
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit() {
            Recorder.leave();
        }
    }

    /** Records a path that does not compile. */
    public static final class Compile {
        private Compile() {
        }

        /** Enters the compilation. */
        @Advice.OnMethodEnter
        public static void enter() {
            Recorder.enter();
        }

        /**
         * Records the path where an outermost compilation throws.
         *
         * @param path the path text
         * @param filters the Predicate arguments
         * @param thrown what the compilation threw, or null
         */
        @Advice.OnMethodExit(onThrowable = Throwable.class)
        public static void exit(@Advice.Argument(0) final String path,
                @Advice.Argument(1) final Predicate[] filters,
                @Advice.Thrown final Throwable thrown) {
            if (Recorder.leave() == 0 && thrown != null) {
                Recorder.compileError(path,
                        filters == null ? 0 : filters.length);
            }
        }
    }

    /**
     * Enters a read or a compilation on this thread.
     *
     * @return the number of reads and compilations the thread was already in
     */
    public static int enter() {
        return DEPTH.get()[0]++;
    }

    /**
     * Leaves a read or a compilation on this thread.
     *
     * @return the number of reads and compilations the thread is still in
     */
    public static int leave() {
        return --DEPTH.get()[0];
    }

    /**
     * Remembers the path text {@code self} was compiled from.
     *
     * @param self the new JsonPath
     * @param path the path text
     * @param filters the number of Predicate arguments
     */
    public static void compiled(final Object self, final String path,
            final int filters) {
        PATHS.put(self, filters == 0 ? path : null);
    }

    /**
     * Records a read of {@code self} over the document {@code doc}.
     *
     * @param self the JsonPath being read
     * @param doc the document as JSON text, or null where JSON cannot hold it
     */
    public static void read(final Object self, final String doc) {
        String path = PATHS.get(self);
        if (path == null) {
            WITH_PREDICATES.incrementAndGet();
        } else if (doc == null) {
            NOT_JSON.incrementAndGet();
        } else {
            write(path, ",\"doc\":" + quote(doc));
        }
    }

    /**
     * Records a path that does not compile.
     *
     * @param path the path text
     * @param filters the number of Predicate arguments
     */
    public static void compileError(final String path, final int filters) {
        if (filters != 0) {
            WITH_PREDICATES.incrementAndGet();
            return;
        }
        write(path, ",\"compileError\":true");
    }

    /**
     * Returns {@code v} as JSON text.
     *
     * @param v a document made of maps, lists, strings, numbers, booleans,
     *     and nulls
     * @return the JSON text
     * @throws IllegalArgumentException where {@code v} holds anything else,
     *     or a double that is not finite
     */
    public static String toJson(final Object v) {
        StringBuilder sb = new StringBuilder();
        append(sb, v);
        return sb.toString();
    }

    private static void append(final StringBuilder sb, final Object v) {
        if (v == null || v instanceof Boolean) {
            sb.append(v);
        } else if (v instanceof String) {
            sb.append(quote((String) v));
        } else if (v instanceof Integer || v instanceof Long
                || v instanceof Short || v instanceof Byte
                || v instanceof BigInteger) {
            sb.append(v);
        } else if (v instanceof BigDecimal) {
            sb.append(((BigDecimal) v).toString());
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("not finite: " + d);
            }
            sb.append(v);
        } else if (v instanceof Map) {
            sb.append('{');
            String sep = "";
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!(e.getKey() instanceof String)) {
                    throw new IllegalArgumentException("key " + e.getKey());
                }
                sb.append(sep).append(quote((String) e.getKey())).append(':');
                append(sb, e.getValue());
                sep = ",";
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            String sep = "";
            for (Object e : (List<?>) v) {
                sb.append(sep);
                append(sb, e);
                sep = ",";
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException(v.getClass().getName());
        }
    }

    private static synchronized void write(final String path,
            final String rest) {
        String test = testName();
        int seq = SEQ.computeIfAbsent(test, k -> new AtomicInteger())
                .incrementAndGet();
        String line = "{\"test\":" + quote(test) + ",\"seq\":" + seq
                + ",\"path\":" + quote(path) + rest + "}\n";
        try {
            out.write(line.getBytes(StandardCharsets.UTF_8));
            out.flush();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        RECORDED.incrementAndGet();
    }

    /**
     * Names the test method on the stack: the frame that reflection invoked.
     * JUnit invokes every test and fixture method that way.
     *
     * @return the method as {@code Class.method}, with the class name
     *     relative to {@code com.jayway.jsonpath}, or {@code unknown} where
     *     no frame was invoked by reflection
     */
    private static String testName() {
        StackTraceElement[] stack = new Throwable().getStackTrace();
        for (int i = 1; i < stack.length; i++) {
            String c = stack[i].getClassName();
            if (c.startsWith("jdk.internal.reflect.")
                    || c.startsWith("sun.reflect.")
                    || c.equals("java.lang.reflect.Method")) {
                StackTraceElement test = stack[i - 1];
                String cls = test.getClassName();
                if (cls.startsWith(JAYWAY_PACKAGE)) {
                    cls = cls.substring(JAYWAY_PACKAGE.length());
                }
                return cls + "." + test.getMethodName();
            }
        }
        return "unknown";
    }

    private static String quote(final String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < ' ') {
                sb.append(String.format("\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.append('"').toString();
    }
}
