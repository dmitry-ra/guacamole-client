package org.dmitryra.guacamole;

import java.util.Map;
import java.util.Arrays;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import org.apache.guacamole.form.EnumField;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleSecurityException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.TokenInjectingUserContext;
import org.apache.guacamole.net.auth.User;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.GuacamoleInsufficientCredentialsException;
import org.apache.guacamole.properties.StringGuacamoleProperty;

/**
 * Personal portal identity selection and mandatory enrollment guard.
 * Authentication is completed by the separately mandatory official TOTP
 * decorator, never by this class alone. See README before packaging.
 */
public final class PortalAuthenticationProvider extends AbstractAuthenticationProvider {
    private final String owner;
    private final Environment environment;
    private final CredentialReader reader;

    @FunctionalInterface
    interface CredentialReader {
        String read(String alias, String protocol) throws GuacamoleException;
    }

    public PortalAuthenticationProvider() throws GuacamoleException {
        this(LocalEnvironment.getInstance());
    }

    PortalAuthenticationProvider(Environment environment) throws GuacamoleException {
        this(environment, PortalAuthenticationProvider::readCredential);
    }

    PortalAuthenticationProvider(Environment environment, CredentialReader reader) throws GuacamoleException {
        this.environment = environment;
        this.reader = reader;
        this.owner = property("portal-user");
        require(owner != null && owner.matches("[a-z][a-z0-9_-]{0,31}")
                && !"guacadmin".equals(owner));
        checkConfiguration();
    }

    private String property(final String name) throws GuacamoleException {
        return environment.getProperty(new StringGuacamoleProperty() {
            @Override public String getName() { return name; }
        });
    }

    private static void require(boolean condition) throws GuacamoleSecurityException {
        if (!condition) throw new GuacamoleSecurityException("Portal authentication unavailable");
    }

    private static void guard(boolean condition, String stage) throws GuacamoleSecurityException {
        if (!condition) System.err.println("HOMELAB_AUTH_GUARD_DENIED " + stage);
        require(condition);
    }

    private void checkConfiguration() throws GuacamoleException {
        require("portal, postgresql, totp, ban".equals(property("extension-priority")));
        require("true".equals(property("postgresql-user-required")));
        require("false".equals(property("postgresql-auto-create-accounts")));
        require(property("skip-if-unavailable") == null);
        require(property("totp-bypass-hosts") == null);
        require(property("totp-enforce-hosts") == null);
        require("6".equals(property("totp-digits")));
        require("30".equals(property("totp-period")));
        require("sha1".equals(property("totp-mode")));
        targets();
    }

    private List<String> targets() throws GuacamoleException {
        String configured = property("portal-targets");
        require(configured != null);
        List<String> targets = List.of(configured.split(",", -1));
        require(!targets.isEmpty() && targets.size() <= 32 && Set.copyOf(targets).size() == targets.size());
        Set<String> identifiers = new HashSet<>();
        for (String target : targets) {
            require(target.length() <= 48 && target.matches("[a-z][a-z0-9]*(?:-[a-z0-9]+)*"));
            String id = property("portal-target-" + target + "-id");
            require(id != null && id.matches("[1-9][0-9]*"));
            require(identifiers.add(id));
            protocol(target);
        }
        return targets;
    }

    private String protocol(String alias) throws GuacamoleException {
        String value = property("portal-target-" + alias + "-protocol");
        require("rdp".equals(value) || "ssh".equals(value));
        return value;
    }

    private static byte[] field(ByteBuffer buffer) throws GuacamoleException {
        require(buffer.remaining() >= 4);
        int size = buffer.getInt();
        require(size >= 0 && size <= buffer.remaining());
        byte[] value = new byte[size];
        buffer.get(value);
        return value;
    }

    static String validateCredential(String protocol, String secret) throws GuacamoleException {
        require(secret != null && !secret.contains("\0"));
        int length = secret.getBytes(StandardCharsets.UTF_8).length;
        if ("rdp".equals(protocol)) {
            require(length > 0 && length <= 512 && !secret.contains("\n") && !secret.contains("\r"));
            return secret;
        }
        require("ssh".equals(protocol) && length > 0 && length <= 16384);
        require(secret.matches("-----BEGIN OPENSSH PRIVATE KEY-----\\n[A-Za-z0-9+/=\\n]+-----END OPENSSH PRIVATE KEY-----\\n?"));
        try {
            String payload = secret.substring("-----BEGIN OPENSSH PRIVATE KEY-----\n".length(),
                    secret.indexOf("-----END OPENSSH PRIVATE KEY-----")).replace("\n", "");
            ByteBuffer data = ByteBuffer.wrap(Base64.getDecoder().decode(payload));
            byte[] magic = "openssh-key-v1\0".getBytes(StandardCharsets.US_ASCII);
            require(data.remaining() >= magic.length);
            byte[] actualMagic = new byte[magic.length]; data.get(actualMagic);
            require(Arrays.equals(magic, actualMagic));
            require(Arrays.equals(field(data), "none".getBytes(StandardCharsets.US_ASCII)));
            require(Arrays.equals(field(data), "none".getBytes(StandardCharsets.US_ASCII)));
            require(field(data).length == 0 && data.remaining() >= 4 && data.getInt() == 1);
            ByteBuffer publicBlob = ByteBuffer.wrap(field(data));
            byte[] privateBytes = field(data);
            require(!data.hasRemaining() && privateBytes.length >= 8 && privateBytes.length % 8 == 0);
            require(Arrays.equals(field(publicBlob), "ssh-ed25519".getBytes(StandardCharsets.US_ASCII)));
            byte[] publicKey = field(publicBlob);
            require(publicKey.length == 32 && !publicBlob.hasRemaining());
            ByteBuffer privateBlob = ByteBuffer.wrap(privateBytes);
            require(privateBlob.getInt() == privateBlob.getInt());
            require(Arrays.equals(field(privateBlob), "ssh-ed25519".getBytes(StandardCharsets.US_ASCII)));
            require(Arrays.equals(field(privateBlob), publicKey));
            byte[] privateKey = field(privateBlob);
            require(privateKey.length == 64 && Arrays.equals(Arrays.copyOfRange(privateKey, 32, 64), publicKey));
            field(privateBlob); // Private key comment is never logged or returned separately.
            int padding = privateBlob.remaining();
            require(padding >= 1 && padding <= 8);
            for (int i = 1; i <= padding; i++) require(privateBlob.get() == i);
            return secret;
        }
        catch (IllegalArgumentException | java.nio.BufferUnderflowException error) {
            throw new GuacamoleSecurityException("Invalid bounded SSH credential");
        }
    }

    private static String readCredential(String alias, String protocol) throws GuacamoleException {
        String parameter = "rdp".equals(protocol) ? "password" : "private-key";
        Path path = Path.of("/run/web-rdp/java/target-" + alias + "-" + parameter);
        try {
            require(!Files.isSymbolicLink(path) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS));
            require(((Integer) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS)) == 2001);
            require(((Integer) Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS)) == 1);
            require(Files.getPosixFilePermissions(path).equals(Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            require(Files.size(path) > 0 && Files.size(path) <= ("rdp".equals(protocol) ? 512 : 16384));
            return validateCredential(protocol, Files.readString(path));
        }
        catch (java.io.IOException error) {
            throw new GuacamoleSecurityException("Connection credential unavailable");
        }
    }

    @Override public String getIdentifier() { return "portal"; }

    @Override public AuthenticatedUser authenticateUser(final Credentials credentials)
            throws GuacamoleException {
        checkConfiguration();
        String name = credentials.getUsername();
        if (name == null || name.isEmpty()) {
            List<Field> fields = new ArrayList<>();
            fields.add(CredentialsInfo.USERNAME);
            if ("true".equals(property("portal-publish-target-labels")))
                fields.add(new EnumField("wrdp-target", targets()));
            throw new GuacamoleInsufficientCredentialsException("Username required",
                    new CredentialsInfo(fields));
        }
        // Terminal rejection prevents JDBC password/sharing-link fallback.
        require(owner.equals(name));
        return new AbstractAuthenticatedUser(true) {
            { setIdentifier(owner); }
            @Override public AuthenticationProvider getAuthenticationProvider() {
                return PortalAuthenticationProvider.this;
            }
            @Override public Credentials getCredentials() { return credentials; }
        };
    }

    @Override public AuthenticatedUser updateAuthenticatedUser(AuthenticatedUser user,
            Credentials credentials) throws GuacamoleException {
        checkConfiguration();
        require(user.getAuthenticationProvider() == this && owner.equals(user.getIdentifier()));
        // Existing token renewal does not demand another OTP, like official TOTP.
        return user;
    }

    @Override public UserContext decorate(UserContext context, AuthenticatedUser user,
            Credentials credentials) throws GuacamoleException {
        checkConfiguration();
        guard(user.getAuthenticationProvider() == this && owner.equals(user.getIdentifier()), "identity");
        guard("postgresql".equals(context.getAuthenticationProvider().getIdentifier()), "context_origin");
        User self = context.self();
        guard(self != null && owner.equals(self.getIdentifier()) && !self.isDisabled(), "account");
        guard(user.getEffectiveUserGroups().isEmpty(), "effective_groups");
        // This portal has no groups. Rejecting membership also closes inherited
        // TOTP-disable policy and avoids custom recursive group resolution.
        guard(self.getUserGroups().getObjects().isEmpty(), "direct_groups");
        Map<String, String> attributes = self.getAttributes();
        guard(attributes != null, "attributes");
        guard("true".equals(attributes.get("guac-totp-key-confirmed")), "confirmation");
        guard(!"true".equals(attributes.get("guac-totp-disabled")), "bypass");
        // Reject malformed stored keys before the mandatory TOTP decorator.
        // This appliance intentionally fixes enrollment to SHA1/6/30.
        // Never log or return the enrollment secret.
        String key = attributes.get("guac-totp-key-secret");
        guard(key != null && key.matches("[A-Z2-7]{32}"), "key_shape");
        return new TokenInjectingUserContext(context) {
            @Override protected Map<String, String> getTokens(Connection connection)
                    throws GuacamoleException {
                // The supported wrapper injects only at connect(), after TOTP
                // has completed. Connection JSON retains the placeholder.
                String selected = null;
                for (String target : targets()) {
                    if (connection.getIdentifier().equals(property("portal-target-" + target + "-id"))) {
                        require(selected == null);
                        selected = target;
                    }
                }
                require(selected != null);
                // JDBC deliberately denies parameter reads to this READ-only
                // user. Runtime database_health() verifies the complete exact
                // connection parameter set against fixed root configuration
                // before Java starts; the portal cannot change that set.
                String protocol = protocol(selected);
                String secret = validateCredential(protocol, reader.read(selected, protocol));
                String suffix = "rdp".equals(protocol) ? "_PASSWORD" : "_PRIVATE_KEY";
                return Map.of("PORTAL_TARGET_" + selected.replace('-', '_').toUpperCase(java.util.Locale.ROOT)
                        + suffix, secret);
            }
        };
    }

    @Override public UserContext redecorate(UserContext decorated, UserContext context,
            AuthenticatedUser user, Credentials credentials) throws GuacamoleException {
        return decorate(context, user, credentials);
    }
}
