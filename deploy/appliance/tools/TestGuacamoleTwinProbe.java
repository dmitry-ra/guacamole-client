import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Inert parser/API checks: never starts the probe or opens a socket. */
public final class TestGuacamoleTwinProbe {
    static int checks;
    static String fixture() {
        return "guacd.host=127.0.0.1\nguacd.port=4822\nclient.width=1100\nclient.height=800\n"
                + "client.dpi=96\nclient.timezone=Etc/UTC\nmedia.audio.count=2\n"
                + "media.audio.0=audio/L16;rate=44100,channels=2\nmedia.audio.1=audio/ogg\n"
                + "media.video.count=0\nmedia.image.count=2\nmedia.image.0=image/webp\nmedia.image.1=image/png\n"
                + "target.1.parameter.hostname=127.0.0.1\ntarget.1.parameter.port=33390\n"
                + "target.1.parameter.username=pb0123456789\ntarget.1.parameter.password=synthetic-one\n"
                + "target.2.parameter.hostname=127.0.0.1\ntarget.2.parameter.port=33389\n"
                + "target.2.parameter.username=paabcdef0123\ntarget.2.parameter.password=synthetic-two\n"
                + constraints(1) + constraints(2);
    }
    static String constraints(int n) {
        String p = "target." + n + ".parameter.";
        return p + "security=tls\n" + p + "domain=\n" + p + "enable-drive=false\n"
                + p + "enable-printing=false\n" + p + "cert-fingerprints=sha256:"
                + "ab:".repeat(31) + "ab\n";
    }
    static GuacamoleTwinProbe.Input parse(String s) throws Exception {
        return new GuacamoleTwinProbe.Input(new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8)));
    }
    static void check(boolean ok) {
        checks++;
        if (!ok) throw new AssertionError("inert check " + checks);
    }
    static void reject(String s) throws Exception {
        try { parse(s); } catch (IllegalArgumentException e) { checks++; return; }
        throw new AssertionError("accepted invalid fixture");
    }
    public static void main(String[] args) throws Exception {
        String f = fixture();
        var input = parse(f);
        var info = input.info();
        check(info.getOptimalScreenWidth() == 1100 && info.getOptimalScreenHeight() == 800);
        check(info.getOptimalResolution() == 96 && info.getTimezone().equals("Etc/UTC"));
        check(info.getAudioMimetypes().equals(List.of("audio/L16;rate=44100,channels=2", "audio/ogg")));
        check(info.getVideoMimetypes().isEmpty());
        check(info.getImageMimetypes().equals(List.of("image/webp", "image/png")));
        check(input.config(1).getParameter("password").equals("synthetic-one"));
        check(input.config(2).getParameter("password").equals("synthetic-two"));
        check(input.config(1).getProtocol().equals("rdp") && info.getName() == null);
        reject(f + "guacd.port=4823\n");
        reject(f.replace("client.width=1100\n", ""));
        reject(f.replace("media.video.count=0\n", ""));
        reject(f.replace("media.image.count=2", "media.image.count=33"));
        reject(f.replace("media.image.1=image/png\n", ""));
        reject(f + "media.image.2=image/jpeg\n");
        reject(f.replace("media.image.1=", "media.image.01="));
        reject(f.replace("guacd.host=127.0.0.1", "guacd.host=localhost"));
        reject(f.replace("guacd.port=4822", "guacd.port=65536"));
        reject(f.replace("client.dpi=96", "client.dpi=0"));
        reject(f + "unknown=ignored\n");
        reject(f.replace("target.2.parameter.password=synthetic-two\n", ""));
        reject(f.replace("guacd.host=127.0.0.1", "guacd.host=192.0.2.1"));
        reject(f.replace("guacd.port=4822", "guacd.port=4823"));
        reject(f.replace("target.1.parameter.hostname=127.0.0.1", "target.1.parameter.hostname=192.0.2.1"));
        reject(f.replace("target.1.parameter.port=33390", "target.1.parameter.port=33389"));
        reject(f.replace("target.1.parameter.port=33390", "target.1.parameter.port=3389"));
        reject(f.replace("security=tls", "security=nla"));
        reject(f.replace("domain=\n", "domain=EXAMPLE\n"));
        reject(f.replace("username=pb0123456789", "username=administrator"));
        reject(f.replace("username=pb0123456789", "username=portal123b"));
        reject(f.replace("username=pb0123456789", "username=pb012345678"));
        reject(f.replace("username=pb0123456789", "username=pb01234567890"));
        reject(f.replace("username=pb0123456789", "username=pb012345678G"));
        reject(f.replace("username=pb0123456789", "username=pc0123456789"));
        check(input.config(1).getParameter("username").equals("pb0123456789"));
        check(input.config(2).getParameter("username").equals("paabcdef0123"));
        reject(f.replace("enable-drive=false", "enable-drive=true"));
        reject(f.replace("enable-printing=false\n", ""));
        reject(f.replace("cert-fingerprints=sha256:", "cert-fingerprints=sha1:"));
        reject(f.replace("ab:".repeat(31) + "ab", "ab:".repeat(30) + "ab"));
        reject(f.replace("ab:".repeat(31) + "ab", "ab:".repeat(31) + "ab,sha256:bad"));
        reject(f + "target.1.parameter.enable-sftp=true\n");
        check(parse(f.replace("port=33390", "port=SWAP").replace("port=33389", "port=33390")
                .replace("port=SWAP", "port=33389")).config(1).getParameter("port").equals("33389"));
        reject("x".repeat(65537));
        check(GuacamoleTwinProbe.WINDOW_MS == 29000);
        System.out.println("{\"inert_checks\":" + checks + ",\"connections\":0}");
    }
}
