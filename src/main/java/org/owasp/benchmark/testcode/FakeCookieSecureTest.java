/**
 * CWE-614 rule true-negative probe (NOT part of the scored OWASP Benchmark).
 *
 * <p>This file is a copy of the shape of BenchmarkTest00087 (securecookie / CWE-614), but every
 * cookie/response object here is a locally-defined FAKE type that merely happens to expose methods
 * named {@code setSecure}, {@code setValue}, {@code setPath}, {@code setHttpOnly} and {@code
 * addCookie}. None of them are {@code javax.servlet.http.Cookie}, {@code HttpServletResponse}, or
 * any Micronaut cookie type.
 *
 * <p>Purpose: verify that the CWE-614 pattern rules match their sink against the real cookie/response
 * TYPE, not merely against a method name. A correctly type-constrained rule must produce NO finding
 * in this file. If a finding is raised here it means the sink is matching by method name alone (a
 * false positive) — see the trailing catch-all clauses in cwe614-*.dl:
 *
 *   literal(L, "BooleanLiteralExpr", "false"), call_argument(N, 0, L), call(N, _, "setSecure", ...)
 *
 * @created 2026 (custom probe)
 */
package org.owasp.benchmark.testcode;

public class FakeCookieSecureTest {

    /**
     * A fake cookie. Same method names as javax.servlet.http.Cookie, but this is a plain POJO in
     * the testcode package — not the servlet Cookie type and not a Micronaut cookie type.
     */
    static class FakeCookie {
        private String name;
        private String value;

        FakeCookie(String name, String value) {
            this.name = name;
            this.value = value;
        }

        void setValue(String value) {
            this.value = value;
        }

        void setSecure(boolean flag) {
            // no-op: this is not a real cookie, there is nothing secure to set
        }

        void setHttpOnly(boolean flag) {
            // no-op
        }

        void setPath(String path) {
            // no-op
        }

        String getName() {
            return name;
        }

        String getValue() {
            return value;
        }
    }

    /**
     * A fake response. Exposes addCookie(...) like HttpServletResponse, but is not a servlet
     * response type.
     */
    static class FakeResponse {
        void addCookie(FakeCookie cookie) {
            // no-op: nothing is actually sent to any client
        }
    }

    /**
     * Probe 1: setSecure(false) on a fake cookie that is then added to a fake response.
     *
     * <p>Mirrors the true-positive shape of BenchmarkTest00087.doPost, but on fake types. Expected:
     * NO CWE-614 finding, because FakeCookie is not a real cookie type.
     */
    public void secureFalseOnFakeCookie(String str) {
        FakeCookie cookie = new FakeCookie("SomeCookie", str);
        cookie.setSecure(false);
        cookie.setHttpOnly(true);
        cookie.setPath("/fake");
        FakeResponse response = new FakeResponse();
        response.addCookie(cookie);
    }

    /**
     * Probe 2: a fake cookie added to a fake response with NO setSecure call at all.
     *
     * <p>Mirrors the "missing secure flag" servlet sink. Expected: NO CWE-614 finding, because
     * neither type is a real cookie/response.
     */
    public void missingSecureOnFakeCookie(String str) {
        FakeCookie cookie = new FakeCookie("AnotherCookie", str);
        cookie.setValue(str);
        cookie.setPath("/fake");
        FakeResponse response = new FakeResponse();
        response.addCookie(cookie);
    }

    /**
     * Probe 3: a builder-style fake with a secure(false) call, echoing the Micronaut Cookie.of(...)
     * / .secure(false) sink. Expected: NO CWE-614 finding.
     */
    public FakeCookieBuilder secureFalseOnFakeBuilder(String value) {
        return new FakeCookieBuilder("SomeCookie", value).secure(false);
    }

    static class FakeCookieBuilder {
        private final String name;
        private final String value;

        FakeCookieBuilder(String name, String value) {
            this.name = name;
            this.value = value;
        }

        FakeCookieBuilder secure(boolean flag) {
            // no-op: fake builder, not io.micronaut.http.cookie.Cookie
            return this;
        }
    }
}
