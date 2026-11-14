package org.dmitryra.guacamole;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import java.util.Collections;
import org.apache.guacamole.net.RequestDetails;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.properties.GuacamoleProperty;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.RelatedObjectSet;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.credentials.GuacamoleInsufficientCredentialsException;

/** Inert provider checks. No HTTP server, live identity, secret files or TOTP calls. */
public final class PortalProviderTest {
    private static void check(boolean value) {
        if (!value) throw new AssertionError();
    }

    private static Map<String, String> properties() {
        Map<String, String> props = new HashMap<>();
        props.put("portal-user", "operator");
        props.put("extension-priority", "portal, postgresql, totp, ban");
        props.put("postgresql-user-required", "true");
        props.put("postgresql-auto-create-accounts", "false");
        props.put("totp-digits", "6"); props.put("totp-period", "30"); props.put("totp-mode", "sha1");
        props.put("portal-targets", "desktop-a,desktop-b");
        props.put("portal-target-desktop-a-id", "17");
        props.put("portal-target-desktop-b-id", "92");
        props.put("portal-target-desktop-a-protocol", "rdp");
        props.put("portal-target-desktop-b-protocol", "rdp");
        props.put("portal-publish-target-labels", "true");
        return props;
    }

    private static Environment environment(Map<String, String> props) {
        return (Environment) Proxy.newProxyInstance(Environment.class.getClassLoader(),
                new Class<?>[]{Environment.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("getProperty"))
                        return props.get(((GuacamoleProperty<?>) arguments[0]).getName());
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static Credentials credentials(String username) {
        return new Credentials(username, null, (RequestDetails) null);
    }

    private static UserContext context(Map<String, String> attributes) {
        return context(attributes, null);
    }

    private static UserContext context(Map<String, String> attributes, Directory<Connection> connections) {
        RelatedObjectSet groups = (RelatedObjectSet) Proxy.newProxyInstance(RelatedObjectSet.class.getClassLoader(),
                new Class<?>[]{RelatedObjectSet.class}, (proxy, method, args) -> Collections.emptySet());
        User user = (User) Proxy.newProxyInstance(User.class.getClassLoader(),
                new Class<?>[]{User.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getIdentifier" -> "operator";
                    case "isDisabled" -> false;
                    case "getAttributes" -> attributes;
                    case "getUserGroups" -> groups;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        AbstractAuthenticationProvider database = new AbstractAuthenticationProvider() {
            @Override public String getIdentifier() { return "postgresql"; }
        };
        return (UserContext) Proxy.newProxyInstance(UserContext.class.getClassLoader(),
                new Class<?>[]{UserContext.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "self" -> user;
                    case "getConnectionDirectory" -> connections;
                    case "getAuthenticationProvider" -> database;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static void field(DataOutputStream out, byte[] value) throws Exception {
        out.writeInt(value.length); out.write(value);
    }

    private static String formatOnlyKey() throws Exception { return formatOnlyKey("none"); }

    private static String formatOnlyKey(String cipher) throws Exception {
        // Structural test fixture only; never an installed/authenticated identity.
        byte[] publicKey = new byte[32];
        for (int i = 0; i < 32; i++) publicKey[i] = (byte) i;
        ByteArrayOutputStream publicBytes = new ByteArrayOutputStream();
        DataOutputStream pub = new DataOutputStream(publicBytes);
        field(pub, "ssh-ed25519".getBytes()); field(pub, publicKey);
        ByteArrayOutputStream privateBytes = new ByteArrayOutputStream();
        DataOutputStream priv = new DataOutputStream(privateBytes);
        priv.writeInt(7); priv.writeInt(7); field(priv, "ssh-ed25519".getBytes()); field(priv, publicKey);
        byte[] privateKey = new byte[64]; System.arraycopy(publicKey, 0, privateKey, 32, 32);
        field(priv, privateKey); field(priv, "synthetic".getBytes());
        int padding = 8 - privateBytes.size() % 8;
        for (int i = 1; i <= padding; i++) priv.write(i);
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(data);
        out.write("openssh-key-v1\0".getBytes()); field(out, cipher.getBytes()); field(out, "none".getBytes());
        field(out, new byte[0]); out.writeInt(1); field(out, publicBytes.toByteArray()); field(out, privateBytes.toByteArray());
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n"+Base64.getEncoder().encodeToString(data.toByteArray())
                +"\n-----END OPENSSH PRIVATE KEY-----\n";
    }

    @SuppressWarnings("unchecked")
    private static void mixedInjection(Map<String, String> attributes) throws Exception {
        Map<String, String> props = properties();
        props.put("portal-targets", "desktop-a,desktop-b,terminal-c");
        props.put("portal-target-terminal-c-id", "93");
        props.put("portal-target-terminal-c-protocol", "ssh");
        String key = formatOnlyKey();
        check(PortalAuthenticationProvider.validateCredential("ssh", key).equals(key));
        for (String invalid : List.of("invalid", key.replace("OPENSSH", "RSA"), key.replace('\n','\r'), key+"unexpected", formatOnlyKey("aes256-ctr"), key.repeat(100))) {
            try { PortalAuthenticationProvider.validateCredential("ssh", invalid); throw new AssertionError(); }
            catch (GuacamoleSecurityException expected) {}
        }
        for (String invalid : List.of(key, "a\nb", "a\0b", "x".repeat(513))) {
            try { PortalAuthenticationProvider.validateCredential("rdp", invalid); throw new AssertionError(); }
            catch (GuacamoleSecurityException expected) {}
        }
        List<Map<String, String>> injected = new ArrayList<>();
        List<String> reads = new ArrayList<>();
        Directory<Connection> directory = (Directory<Connection>) Proxy.newProxyInstance(Directory.class.getClassLoader(),
            new Class<?>[]{Directory.class}, (proxy, method, args) -> {
                if (!method.getName().equals("get")) throw new UnsupportedOperationException();
                String id = (String) args[0];
                return Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},
                    (object, operation, values) -> switch (operation.getName()) {
                        case "getIdentifier" -> id;
                        case "connect" -> { injected.add(new HashMap<>((Map<String,String>) values[1])); yield null; }
                        default -> throw new UnsupportedOperationException(operation.getName());
                    });
            });
        PortalAuthenticationProvider provider = new PortalAuthenticationProvider(environment(props), (alias, protocol) -> {
            reads.add(alias+":"+protocol);
            return protocol.equals("ssh") ? key : "synthetic-"+alias;
        });
        AuthenticatedUser identity = provider.authenticateUser(credentials("operator"));
        UserContext wrapped = provider.decorate(context(attributes, directory), identity, credentials("operator"));
        for (String id : List.of("17", "92", "93"))
            wrapped.getConnectionDirectory().get(id).connect(new GuacamoleClientInformation(), Map.of());
        check(reads.equals(List.of("desktop-a:rdp","desktop-b:rdp","terminal-c:ssh")));
        check(injected.get(0).equals(Map.of("PORTAL_TARGET_DESKTOP_A_PASSWORD","synthetic-desktop-a")));
        check(injected.get(1).equals(Map.of("PORTAL_TARGET_DESKTOP_B_PASSWORD","synthetic-desktop-b")));
        check(injected.get(2).equals(Map.of("PORTAL_TARGET_TERMINAL_C_PRIVATE_KEY",key)));
        try { wrapped.getConnectionDirectory().get("999").connect(new GuacamoleClientInformation(), Map.of()); throw new AssertionError(); }
        catch (GuacamoleSecurityException expected) {}
        check(reads.size() == 3 && injected.size() == 3);
        PortalAuthenticationProvider invalidReader = new PortalAuthenticationProvider(environment(props),
                (alias, protocol) -> "invalid-key");
        UserContext invalidContext = invalidReader.decorate(context(attributes, directory),
                invalidReader.authenticateUser(credentials("operator")), credentials("operator"));
        try { invalidContext.getConnectionDirectory().get("93").connect(new GuacamoleClientInformation(), Map.of()); throw new AssertionError(); }
        catch (GuacamoleSecurityException expected) {}
        check(injected.size() == 3);

        props.put("portal-target-terminal-c-protocol", "telnet");
        try { new PortalAuthenticationProvider(environment(props)); throw new AssertionError(); }
        catch (GuacamoleSecurityException expected) {}
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> props = properties();
        PortalAuthenticationProvider provider = new PortalAuthenticationProvider(environment(props));
        try {
            provider.authenticateUser(credentials(null)); throw new AssertionError();
        }
        catch (GuacamoleInsufficientCredentialsException expected) {
            check(expected.getCredentialsInfo().getFields().size() == 2);
        }
        props.put("portal-publish-target-labels", "false");
        try {
            provider.authenticateUser(credentials(null)); throw new AssertionError();
        }
        catch (GuacamoleInsufficientCredentialsException expected) {
            check(expected.getCredentialsInfo().getFields().size() == 1);
        }
        try {
            provider.authenticateUser(credentials("another-user")); throw new AssertionError();
        }
        catch (GuacamoleSecurityException expected) {}
        AuthenticatedUser selected = provider.authenticateUser(credentials("operator"));
        check(selected.getIdentifier().equals("operator"));
        Map<String, String> attributes = new HashMap<>();
        attributes.put("guac-totp-key-confirmed", "true");
        // Public synthetic key shape only; no real TOTP is generated or verified here.
        attributes.put("guac-totp-key-secret", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        check(provider.decorate(context(attributes), selected, credentials("operator")) != null);
        for (Map.Entry<String, String> invalid : List.of(
                Map.entry("guac-totp-key-confirmed", "false"),
                Map.entry("guac-totp-key-secret", "invalid"),
                Map.entry("guac-totp-disabled", "true"))) {
            Map<String, String> changed = new HashMap<>(attributes);
            changed.put(invalid.getKey(), invalid.getValue());
            try {
                provider.decorate(context(changed), selected, credentials("operator"));
                throw new AssertionError();
            }
            catch (GuacamoleSecurityException expected) {}
        }
        for (Map.Entry<String, String> invalid : List.of(
                Map.entry("portal-target-desktop-b-id", "17"),
                Map.entry("portal-target-desktop-b-protocol", "telnet"),
                Map.entry("extension-priority", "postgresql, totp"),
                Map.entry("skip-if-unavailable", "totp"),
                Map.entry("totp-bypass-hosts", "127.0.0.1"))) {
            Map<String, String> changed = properties();
            changed.put(invalid.getKey(), invalid.getValue());
            try {
                new PortalAuthenticationProvider(environment(changed)); throw new AssertionError();
            }
            catch (GuacamoleSecurityException expected) {}
        }
        mixedInjection(attributes);
        check(PortalGateFilter.held(64_000_000_000L, 66_000L));
        check(PortalGateFilter.held(66_000_000_000L, 64_000L));
        check(!PortalGateFilter.held(66_000_000_000L, 66_000L));
        System.out.println("Provider identity/enrollment/catalog/hold checks passed");
    }
}
