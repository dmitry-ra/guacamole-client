import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.*;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.io.*;
import org.apache.guacamole.net.InetGuacamoleSocket;
import org.apache.guacamole.protocol.*;

/** Conditional synthetic-only diagnostic. No product classes are replaced. */
public final class GuacamoleTwinProbe {
    static final int WINDOW_MS = 29000;
    static final class Input {
        final Properties p = new Properties() {
            @Override public synchronized Object put(Object key, Object value) {
                if (containsKey(key)) throw new IllegalArgumentException();
                return super.put(key, value);
            }
        };
        Input(InputStream stream) throws Exception {
            byte[] bytes = stream.readNBytes(65537);
            if (bytes.length > 65536) throw new IllegalArgumentException();
            p.load(new StringReader(new String(bytes, StandardCharsets.UTF_8)));
            for (String k : p.stringPropertyNames()) {
                if (!(Set.of("guacd.host", "guacd.port", "client.width", "client.height",
                        "client.dpi", "client.timezone", "media.audio.count", "media.video.count",
                        "media.image.count").contains(k)
                        || k.matches("media\\.(audio|video|image)\\.[0-9]+")
                        || k.matches("target\\.[12]\\.parameter\\.[a-z][a-z0-9-]{0,63}")))
                    throw new IllegalArgumentException();
                if (p.getProperty(k).length() > 8192) throw new IllegalArgumentException();
            }
            require("guacd.host", "127.0.0.1");
            require("guacd.port", "4822");
            Set<String> parameters = Set.of("hostname", "port", "username", "password", "domain",
                    "security", "cert-fingerprints", "enable-drive", "enable-printing",
                    "resize-method", "enable-font-smoothing", "client-name");
            for (int n = 1; n <= 2; n++) {
                String prefix = "target." + n + ".parameter.";
                for (String key : p.stringPropertyNames())
                    if (key.startsWith(prefix) && !parameters.contains(key.substring(prefix.length())))
                        throw new IllegalArgumentException();
                require(prefix + "hostname", "127.0.0.1");
                if (!Set.of("33389", "33390").contains(value(prefix + "port")))
                    throw new IllegalArgumentException();
                if (!value(prefix + "username").matches("p[ab][0-9a-f]{10}"))
                    throw new IllegalArgumentException();
                if (value(prefix + "password").isEmpty()) throw new IllegalArgumentException();
                require(prefix + "security", "tls");
                require(prefix + "domain", "");
                require(prefix + "enable-drive", "false");
                require(prefix + "enable-printing", "false");
                if (!value(prefix + "cert-fingerprints").matches("sha256:(?:[0-9a-f]{2}:){31}[0-9a-f]{2}"))
                    throw new IllegalArgumentException();
            }
            if (value("target.1.parameter.port").equals(value("target.2.parameter.port")))
                throw new IllegalArgumentException();
            // Construct Guacamole library objects only after fixture constraints pass.
            info();
        }
        void require(String key, String expected) {
            if (!value(key).equals(expected)) throw new IllegalArgumentException();
        }
        String value(String k) {
            String v = p.getProperty(k);
            if (v == null) throw new IllegalArgumentException();
            return v;
        }
        int number(String k, int min, int max) {
            String v = value(k);
            if (!v.matches("0|[1-9][0-9]{0,8}")) throw new IllegalArgumentException();
            int n = Integer.parseInt(v);
            if (n < min || n > max) throw new IllegalArgumentException();
            return n;
        }
        List<String> media(String kind) {
            String prefix = "media." + kind + ".";
            int count = number(prefix + "count", 0, 32);
            List<String> out = new ArrayList<>();
            for (int n = 0; n < count; n++) {
                String v = value(prefix + n);
                if (v.isEmpty() || v.length() > 256 || v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0)
                    throw new IllegalArgumentException();
                out.add(v);
            }
            for (String key : p.stringPropertyNames())
                if (key.startsWith(prefix) && !key.equals(prefix + "count")
                        && !outIndex(key.substring(prefix.length()), count))
                    throw new IllegalArgumentException();
            return out;
        }
        static boolean outIndex(String key, int count) {
            try { int i = Integer.parseInt(key); return i >= 0 && i < count && key.equals("" + i); }
            catch (NumberFormatException e) { return false; }
        }
        GuacamoleClientInformation info() {
            GuacamoleClientInformation i = new GuacamoleClientInformation();
            i.setOptimalScreenWidth(number("client.width", 1, 8192));
            i.setOptimalScreenHeight(number("client.height", 1, 8192));
            i.setOptimalResolution(number("client.dpi", 1, 600));
            String timezone = value("client.timezone");
            ZoneId.of(timezone);
            i.setTimezone(timezone);
            i.getAudioMimetypes().addAll(media("audio"));
            i.getVideoMimetypes().addAll(media("video"));
            i.getImageMimetypes().addAll(media("image"));
            return i;
        }
        GuacamoleConfiguration config(int n) {
            GuacamoleConfiguration c = new GuacamoleConfiguration();
            c.setProtocol("rdp");
            String prefix = "target." + n + ".parameter.";
            for (String key : p.stringPropertyNames())
                if (key.startsWith(prefix)) c.setParameter(key.substring(prefix.length()), value(key));
            return c;
        }
    }

    static int remaining(long deadline) {
        return (int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime()));
    }
    static final class Client {
        final int number;
        volatile InetGuacamoleSocket wire;
        void close() { try { if (wire != null) wire.close(); } catch (GuacamoleException ignored) { } }
        final CountDownLatch syncSeen = new CountDownLatch(1);
        volatile boolean alive;
        volatile int stage, status;
        volatile long instructions, sync, blobs, display, lastRead, readyAt;
        Thread thread;
        Client(int n) { number = n; }
        void start(Input input, ScheduledExecutorService closer) {
            ScheduledFuture<?> limit = closer.schedule(this::close, WINDOW_MS, TimeUnit.MILLISECONDS);
            thread = Thread.ofPlatform().daemon().start(() -> {
                alive = true;
                try {
                    stage = 1;
                    wire = new InetGuacamoleSocket(input.value("guacd.host"), input.number("guacd.port", 1, 65535));
                    stage = 2;
                    ConfiguredGuacamoleSocket configured = new ConfiguredGuacamoleSocket(wire, input.config(number), input.info());
                    limit.cancel(false);
                    readyAt = System.currentTimeMillis();
                    stage = 3;
                    GuacamoleReader reader = configured.getReader();
                    GuacamoleWriter writer = configured.getWriter();
                    GuacamoleInstruction instruction;
                    while ((instruction = reader.readInstruction()) != null) {
                        instructions++;
                        lastRead = System.currentTimeMillis();
                        String op = instruction.getOpcode();
                        List<String> args = instruction.getArgs();
                        if ("sync".equals(op) && !args.isEmpty()) {
                            writer.writeInstruction(new GuacamoleInstruction("sync", args.get(0)));
                            sync++;
                            stage = 4;
                            syncSeen.countDown();
                        }
                        else if ("blob".equals(op) && !args.isEmpty()) {
                            writer.writeInstruction(new GuacamoleInstruction("ack", args.get(0), "OK", "0"));
                            blobs++;
                        }
                        else if (Set.of("png", "jpeg", "img", "rect", "copy", "cfill").contains(op)) display++;
                        else if ("error".equals(op)) {
                            status = args.size() > 1 && args.get(1).matches("[0-9]{1,5}")
                                    ? Integer.parseInt(args.get(1)) : 512;
                            break;
                        }
                        else if ("disconnect".equals(op)) break;
                    }
                }
                catch (GuacamoleException e) { status = e.getStatus().getGuacamoleStatusCode(); }
                catch (Exception e) { status = 512; }
                finally { alive = false; close(); limit.cancel(false); syncSeen.countDown(); }
            });
        }
        String json() {
            return "{\"client\":" + number + ",\"stage\":" + stage + ",\"status\":" + status
                    + ",\"alive\":" + (alive ? 1 : 0) + ",\"instructions\":" + instructions
                    + ",\"sync\":" + sync + ",\"blobs\":" + blobs + ",\"display\":" + display
                    + ",\"ready_ms\":" + readyAt + ",\"last_read_ms\":" + lastRead + "}";
        }
    }
    public static void main(String[] args) {
        // Library exception/log text may contain private parameters. Never emit it.
        PrintStream output = System.out;
        System.setErr(new PrintStream(OutputStream.nullOutputStream()));
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        Thread.ofPlatform().daemon().start(() -> {
            try { Thread.sleep(75000); } catch (InterruptedException ignored) { }
            Runtime.getRuntime().halt(124);
        });
        Client first = new Client(1), second = new Client(2);
        ScheduledExecutorService closer = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r); t.setDaemon(true); return t;
        });
        int result = 1;
        long secondStarted = 0, firstSyncAtSecond = 0;
        try {
            if (args.length != 0) throw new IllegalArgumentException();
            Input input = new Input(System.in);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(65);
            closer.schedule(() -> { first.close(); second.close(); }, 65, TimeUnit.SECONDS);
            first.start(input, closer);
            if (first.syncSeen.await(WINDOW_MS + 1000, TimeUnit.MILLISECONDS) && first.alive && first.sync > 0) {
                secondStarted = System.currentTimeMillis();
                firstSyncAtSecond = first.sync;
                second.start(input, closer);
                boolean secondSync = second.syncSeen.await(Math.min(WINDOW_MS + 1000, remaining(deadline)), TimeUnit.MILLISECONDS);
                if (secondSync && second.sync > 0) Thread.sleep(Math.min(2000, remaining(deadline)));
                if (secondSync && second.sync > 0 && first.alive && second.alive && first.status == 0 && second.status == 0) result = 0;
            }
            output.println("{\"result\":" + result + ",\"timestamp_ms\":" + System.currentTimeMillis()
                    + ",\"second_started_ms\":" + secondStarted + ",\"first_sync_at_second\":" + firstSyncAtSecond
                    + ",\"first_reader_alive\":" + (first.alive ? 1 : 0)
                    + ",\"clients\":[" + first.json() + "," + second.json() + "]}");
        }
        catch (Exception e) { output.println("{\"result\":2,\"status\":512}"); }
        finally {
            first.close(); second.close(); closer.shutdownNow();
        }
        System.exit(result);
    }
}
