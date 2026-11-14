package org.dmitryra.guacamole;

import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.TypeLiteral;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.event.listener.Listener;

/** WAR-level mandatory gate: this is not an optional authentication extension. */
public final class PortalGateFilter implements Filter {
    private long startedNanos;
    private long startedMillis;
    private static final long HOLD_MILLIS = 65_000L;
    private static final List<String> PROVIDERS = List.of(
            "portal", "postgresql", "totp", "default");
    private static final List<String> LISTENERS = List.of(
            "org.apache.guacamole.auth.ban.BanningAuthenticationListener",
            "org.apache.guacamole.event.EventLoggingListener");

    @Override public void init(FilterConfig config) throws ServletException {
        try {
            Object value = config.getServletContext().getAttribute("GUAC_GUICE_INJECTOR");
            if (!(value instanceof Injector)) throw new IllegalStateException();
            Injector injector = (Injector) value;
            List<AuthenticationProvider> auth = injector.getInstance(
                    Key.get(new TypeLiteral<List<AuthenticationProvider>>() {}));
            List<String> identifiers = auth.stream().map(AuthenticationProvider::getIdentifier)
                    .collect(Collectors.toList());
            List<Listener> listeners = injector.getInstance(
                    Key.get(new TypeLiteral<List<Listener>>() {}));
            List<String> names = listeners.stream().map(x -> x.getClass().getName())
                    .collect(Collectors.toList());
            if (!PROVIDERS.equals(identifiers) || !LISTENERS.equals(names))
                throw new IllegalStateException("Required authentication components unavailable");
            startedNanos = System.nanoTime();
            startedMillis = System.currentTimeMillis();
        }
        catch (RuntimeException error) {
            throw new ServletException("Required authentication components unavailable", error);
        }
    }

    static boolean held(long elapsedNanos, long elapsedMillis) {
        return elapsedNanos < HOLD_MILLIS * 1_000_000L || elapsedMillis < HOLD_MILLIS;
    }

    @Override public void doFilter(ServletRequest input, ServletResponse output,
            FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) input;
        // Every non-read request is held, including token routes with alternate
        // encodings. Existing tokens do not survive a fresh JVM.
        if (!List.of("GET", "HEAD").contains(request.getMethod()) && held(
                System.nanoTime() - startedNanos, System.currentTimeMillis() - startedMillis)) {
            HttpServletResponse response = (HttpServletResponse) output;
            response.setStatus(503);
            response.setHeader("Retry-After", "65");
            response.setHeader("Cache-Control", "no-store");
            response.setContentType("application/json");
            response.getWriter().write("{\"type\":\"INTERNAL_ERROR\",\"message\":\"Authentication is warming up; retry in a minute.\"}");
            return;
        }
        chain.doFilter(input, output);
    }

    @Override public void destroy() {}
}
