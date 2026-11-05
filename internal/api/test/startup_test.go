package test

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cpa-usage-keeper/internal/api"
)

func TestStartupShellServesPublicStatusAndStaticPageWithoutDatabase(t *testing.T) {
	staticFS := testStaticFS(t, map[string]string{
		"index.html":    `<html><script>window.__APP_BASE_PATH__ = "__APP_BASE_PATH__";</script></html>`,
		"assets/app.js": "console.log('startup')",
	})
	for _, basePath := range []string{"", "/cpa"} {
		t.Run("base="+basePath, func(t *testing.T) {
			config := api.AuthConfig{BasePath: basePath, FrameAncestorOrigins: []string{"https://cpamc.example"}}
			shell := api.NewStartupShell(staticFS, config, basePath)
			status := requestStartup(t, shell, http.MethodGet, basePath+"/api/v1/startup/status")
			if status.Code != http.StatusOK || status.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("public startup status: code=%d headers=%v", status.Code, status.Header())
			}
			assertStartupJSON(t, status, "opening", true)

			for _, path := range []string{basePath + "/", basePath + "/dashboard/details"} {
				resp := requestStartup(t, shell, http.MethodGet, path)
				if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `window.__APP_BASE_PATH__ = "`+basePath+`";`) {
					t.Fatalf("startup page %s: code=%d body=%s", path, resp.Code, resp.Body.String())
				}
				if got := resp.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'self' https://cpamc.example" {
					t.Fatalf("startup embed CSP=%q", got)
				}
				if resp.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("startup HTML must not be cached: %v", resp.Header())
				}
			}
			asset := requestStartup(t, shell, http.MethodGet, basePath+"/assets/app.js")
			if asset.Code != http.StatusOK || asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
				t.Fatalf("startup asset: code=%d headers=%v", asset.Code, asset.Header())
			}
			liveness := requestStartup(t, shell, http.MethodGet, basePath+"/healthz")
			if liveness.Code != http.StatusOK {
				t.Fatalf("startup liveness code=%d", liveness.Code)
			}
			blocked := requestStartup(t, shell, http.MethodPost, basePath+"/api/v1/pricing/models")
			if blocked.Code != http.StatusServiceUnavailable || !strings.Contains(blocked.Body.String(), `"code":"migration_in_progress"`) {
				t.Fatalf("startup business API: code=%d body=%s", blocked.Code, blocked.Body.String())
			}
			assertAPISecurityHeaders(t, blocked)
			if basePath != "" {
				outside := requestStartup(t, shell, http.MethodGet, "/api/v1/startup/status")
				if outside.Code != http.StatusNotFound {
					t.Fatalf("unprefixed status code=%d", outside.Code)
				}
			}
		})
	}
}

func TestStartupShellKeepsFailedPageAndAtomicReadySwitch(t *testing.T) {
	staticFS := testStaticFS(t, map[string]string{"index.html": `<html>startup</html>`})
	shell := api.NewStartupShell(staticFS, api.AuthConfig{}, "")
	processed := int64(12)
	if err := shell.Publish(api.StartupPhaseMigrating, &api.StartupProgress{ProcessedCount: processed}); err != nil {
		t.Fatalf("publish migrating: %v", err)
	}
	migrating := requestStartup(t, shell, http.MethodGet, "/api/v1/startup/status")
	assertStartupJSON(t, migrating, "migrating", false)
	if !strings.Contains(migrating.Body.String(), `"processed_count":12,"total_count":null`) {
		t.Fatalf("unknown total must stay null: %s", migrating.Body.String())
	}
	total := int64(20)
	if err := shell.Publish(api.StartupPhaseMigrating, &api.StartupProgress{ProcessedCount: processed, TotalCount: &total}); err != nil {
		t.Fatalf("publish known total: %v", err)
	}
	total = 99
	known := requestStartup(t, shell, http.MethodGet, "/api/v1/startup/status")
	if !strings.Contains(known.Body.String(), `"processed_count":12,"total_count":20`) {
		t.Fatalf("published progress changed after caller mutation: %s", known.Body.String())
	}
	if err := shell.Publish(api.StartupPhaseReady, nil); err == nil {
		t.Fatal("Publish made an empty shell ready")
	}
	if err := shell.Publish(api.StartupPhaseFailed, nil); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	failed := requestStartup(t, shell, http.MethodGet, "/api/v1/startup/status")
	assertStartupJSON(t, failed, "failed", true)
	if strings.Contains(failed.Body.String(), "SQL") || strings.Contains(failed.Body.String(), "database") {
		t.Fatalf("failed status disclosed internals: %s", failed.Body.String())
	}
	if page := requestStartup(t, shell, http.MethodGet, "/pricing"); page.Code != http.StatusOK {
		t.Fatalf("failed shell lost startup page: code=%d", page.Code)
	}
	if liveness := requestStartup(t, shell, http.MethodGet, "/healthz"); liveness.Code != http.StatusOK {
		t.Fatalf("failed shell lost liveness route: code=%d", liveness.Code)
	}
	blocked := requestStartup(t, shell, http.MethodGet, "/api/v1/pricing/models")
	if blocked.Code != http.StatusServiceUnavailable {
		t.Fatalf("failed shell exposed business API: code=%d", blocked.Code)
	}
	assertAPISecurityHeaders(t, blocked)
	if err := shell.ActivateReady(nil); err == nil {
		t.Fatal("nil full handler activated ready")
	}
	full := api.NewRouter(staticFS, nil, nil, nil, api.AuthConfig{}, nil, "")
	if err := shell.ActivateReady(full); err != nil {
		t.Fatalf("activate full router: %v", err)
	}
	ready := requestStartup(t, shell, http.MethodGet, "/api/v1/startup/status")
	assertStartupJSON(t, ready, "ready", true)
	if missing := requestStartup(t, shell, http.MethodGet, "/api/v1/unknown"); missing.Code != http.StatusNotFound {
		t.Fatalf("ready router still returned shell error: code=%d", missing.Code)
	}
	if err := shell.Publish(api.StartupPhaseMigrating, nil); err == nil {
		t.Fatal("late startup publisher replaced ready handler")
	}
}

func TestFullRouterStartupStatusIsPublicAndReady(t *testing.T) {
	for _, basePath := range []string{"", "/cpa"} {
		router := api.NewRouter(nil, nil, nil, nil, api.AuthConfig{Enabled: true, BasePath: basePath}, nil, basePath)
		resp := requestStartup(t, router, http.MethodGet, basePath+"/api/v1/startup/status")
		assertStartupJSON(t, resp, "ready", true)
	}
}

func TestStartupAndFullRouterSecurityLimitsCoverMissingAPIRoutes(t *testing.T) {
	for _, basePath := range []string{"", "/cpa"} {
		config := api.AuthConfig{Enabled: true, LoginPassword: "secret", BasePath: basePath}
		shell := api.NewStartupShell(nil, config, basePath)
		failed := api.NewStartupShell(nil, config, basePath)
		if err := failed.Publish(api.StartupPhaseFailed, nil); err != nil {
			t.Fatal(err)
		}
		for name, handler := range map[string]http.Handler{
			"opening": shell,
			"failed":  failed,
			"ready":   api.NewRouter(nil, nil, nil, nil, config, nil, basePath),
		} {
			t.Run(name+"/base="+basePath, func(t *testing.T) {
				// 启动壳通过 NoRoute 响应；完整 Router 可能在登录限额处提前返回。
				for _, endpoint := range []string{"auth/login", "auth/api-key-login", "auth/oidc/login", "unknown", "auth/login/", "auth/api-key-login/", "auth/oidc/login/", "unknown/"} {
					size := 4097
					if strings.HasPrefix(endpoint, "unknown") {
						size = (1 << 20) + 1
					}
					resp := httptest.NewRecorder()
					req := httptest.NewRequest(http.MethodPost, basePath+"/api/v1/"+endpoint, strings.NewReader(strings.Repeat("x", size)))
					handler.ServeHTTP(resp, req)
					if resp.Code != http.StatusRequestEntityTooLarge {
						t.Errorf("%s oversized request: got %d, want 413", endpoint, resp.Code)
					}
					assertAPISecurityHeaders(t, resp)
				}
				missing := requestStartup(t, handler, http.MethodGet, basePath+"/api/v1/unknown")
				assertAPISecurityHeaders(t, missing)
			})
		}
	}
}

func TestTrailingSlashRedirectsRunAfterSecurityMiddleware(t *testing.T) {
	staticFiles := testStaticFS(t, map[string]string{
		"index.html":    `<html>startup</html>`,
		"assets/app.js": "console.log('startup')",
	})
	for _, basePath := range []string{"", "/cpa"} {
		for staticName, staticFS := range map[string]fs.FS{"no static": nil, "with static": staticFiles} {
			config := api.AuthConfig{Enabled: true, BasePath: basePath}
			full := api.NewRouter(staticFS, nil, nil, nil, config, nil, basePath)
			if full.RedirectTrailingSlash || full.RedirectFixedPath {
				t.Fatal("Gin automatic redirects must be explicitly disabled")
			}
			for name, handler := range map[string]http.Handler{
				"startup": api.NewStartupShell(staticFS, config, basePath),
				"ready":   full,
			} {
				t.Run(name+"/base="+basePath+"/"+staticName, func(t *testing.T) {
					for _, endpoint := range []string{"/healthz", "/readyz", "/api/v1/startup/status"} {
						query := "?probe=a%2Fb&probe=second"
						response := requestStartup(t, handler, http.MethodGet, basePath+endpoint+"/"+query)
						if response.Code != http.StatusMovedPermanently || response.Header().Get("Location") != basePath+endpoint+query {
							t.Fatalf("%s redirect: code=%d headers=%v", endpoint, response.Code, response.Header())
						}
						assertAPISecurityHeaders(t, response)
						if endpoint == "/readyz" {
							followed := requestStartup(t, handler, http.MethodGet, response.Header().Get("Location"))
							want := http.StatusOK
							if name == "startup" {
								want = http.StatusServiceUnavailable
							}
							if followed.Code != want || !strings.Contains(followed.Body.String(), `"phase":`) {
								t.Fatalf("readiness fell through to SPA: code=%d body=%s", followed.Code, followed.Body.String())
							}
							assertAPISecurityHeaders(t, followed)
						}
					}
					query := "?code=a%2Fb&state=s%2Bt&state=second&empty="
					for _, endpoint := range []struct{ method, path string }{
						{http.MethodGet, "/api/v1/auth/oidc/callback"},
						{http.MethodGet, "/api/v1/quota/history/example"},
						{http.MethodPatch, "/api/v1/auth/sessions/example"},
					} {
						response := requestStartup(t, handler, endpoint.method, basePath+endpoint.path+"/"+query)
						want := http.StatusServiceUnavailable
						location := ""
						if name == "ready" {
							want = http.StatusTemporaryRedirect
							if endpoint.method == http.MethodGet {
								want = http.StatusMovedPermanently
							}
							location = basePath + endpoint.path + query
						}
						if response.Code != want || response.Header().Get("Location") != location || len(response.Result().Cookies()) != 0 {
							t.Fatalf("%s %s: code=%d headers=%v", endpoint.method, endpoint.path, response.Code, response.Header())
						}
						assertAPISecurityHeaders(t, response)
					}
					for _, endpoint := range []string{"/api/v1/unknown/", "/api/v1/auth/login/", "/api/v1/AUTH/oidc/callback/", "/api/v1/auth/oidc/callback//", "/api/v1/quota/history/../"} {
						response := requestStartup(t, handler, http.MethodGet, basePath+endpoint)
						want := http.StatusNotFound
						if name == "startup" {
							want = http.StatusServiceUnavailable
						}
						if response.Code != want || response.Header().Get("Location") != "" {
							t.Fatalf("unregistered method/path %s redirected: code=%d headers=%v", endpoint, response.Code, response.Header())
						}
						assertAPISecurityHeaders(t, response)
					}
					if basePath != "" {
						for _, endpoint := range []string{"/readyz/", "/api/v1/auth/oidc/callback/"} {
							response := requestStartup(t, handler, http.MethodGet, endpoint)
							if response.Code != http.StatusNotFound || response.Header().Get("Location") != "" {
								t.Fatalf("trailing slash escaped base path: code=%d headers=%v", response.Code, response.Header())
							}
						}
					}
				})
			}
		}
	}
}

func TestTrailingSlashRedirectIgnoresForwardedPrefixAndPreservesEmptyQuery(t *testing.T) {
	for _, basePath := range []string{"", "/cpa"} {
		config := api.AuthConfig{BasePath: basePath}
		for name, handler := range map[string]http.Handler{
			"startup": api.NewStartupShell(nil, config, basePath),
			"ready":   api.NewRouter(nil, nil, nil, nil, config, nil, basePath),
		} {
			t.Run(name+"/base="+basePath, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, "https://untrusted.example"+basePath+"/api/v1/startup/status/?", nil)
				request.Header.Set("X-Forwarded-Prefix", "//other.example/untrusted")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusMovedPermanently || response.Header().Get("Location") != basePath+"/api/v1/startup/status?" {
					t.Fatalf("redirect must remain local and preserve query: code=%d headers=%v", response.Code, response.Header())
				}
				if request.URL.Path != basePath+"/api/v1/startup/status/" {
					t.Fatalf("redirect mutated request path: %q", request.URL.Path)
				}
				assertAPISecurityHeaders(t, response)
			})
		}
	}
}

func TestTrailingSlashFixPreservesStaticAndSPACacheContracts(t *testing.T) {
	staticFS := testStaticFS(t, map[string]string{
		"index.html":    `<html>window.__APP_BASE_PATH__="__APP_BASE_PATH__"</html>`,
		"assets/app.js": "console.log('asset')",
	})
	for _, basePath := range []string{"", "/cpa"} {
		config := api.AuthConfig{BasePath: basePath, FrameAncestorOrigins: []string{"https://cpamc.example"}}
		for name, handler := range map[string]http.Handler{
			"startup": api.NewStartupShell(staticFS, config, basePath),
			"ready":   api.NewRouter(staticFS, nil, nil, nil, config, nil, basePath),
		} {
			t.Run(name+"/base="+basePath, func(t *testing.T) {
				for _, path := range []string{"/", "/dashboard/details/", "/extra/../dashboard/"} {
					response := requestStartup(t, handler, http.MethodGet, basePath+path)
					if response.Code != http.StatusOK || response.Header().Get("Location") != "" || !strings.Contains(response.Body.String(), `window.__APP_BASE_PATH__="`+basePath+`"`) {
						t.Fatalf("SPA %s: code=%d headers=%v body=%s", path, response.Code, response.Header(), response.Body.String())
					}
					if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Security-Policy") != "frame-ancestors 'self' https://cpamc.example" {
						t.Fatalf("SPA cache/CSP changed: %v", response.Header())
					}
				}
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					response := requestStartup(t, handler, method, basePath+"/assets/app.js")
					if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || response.Header().Get("Pragma") != "" || response.Header().Get("Referrer-Policy") != "" {
						t.Fatalf("asset %s cache changed: code=%d headers=%v", method, response.Code, response.Header())
					}
				}
				if basePath != "" {
					response := requestStartup(t, handler, http.MethodGet, basePath+"?tab=overview%2Fdetails")
					if response.Code != http.StatusMovedPermanently || response.Header().Get("Location") != basePath+"/?tab=overview%2Fdetails" || response.Header().Get("Cache-Control") != "no-store" {
						t.Fatalf("base path redirect changed: code=%d headers=%v", response.Code, response.Header())
					}
				}
			})
		}
	}
}

func TestUninitializedStartupShellFailureHasSecurityHeaders(t *testing.T) {
	var nilShell *api.StartupShell
	for _, shell := range []*api.StartupShell{nilShell, {}} {
		resp := requestStartup(t, shell, http.MethodGet, "/api/v1/startup/status")
		if resp.Code != http.StatusServiceUnavailable {
			t.Fatalf("uninitialized shell status=%d", resp.Code)
		}
		assertAPISecurityHeaders(t, resp)
	}
}

func requestStartup(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(method, path, nil))
	return resp
}

func assertStartupJSON(t *testing.T, resp *httptest.ResponseRecorder, phase string, wantNullProgress bool) {
	t.Helper()
	if resp.Code != http.StatusOK {
		t.Fatalf("startup status code=%d body=%s", resp.Code, resp.Body.String())
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(resp.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode startup status: %v", err)
	}
	if string(value["phase"]) != `"`+phase+`"` || len(value["message"]) == 0 {
		t.Fatalf("unexpected startup status: %s", resp.Body.String())
	}
	if wantNullProgress && string(value["progress"]) != "null" {
		t.Fatalf("unknown progress must be null: %s", resp.Body.String())
	}
	assertAPISecurityHeaders(t, resp)
}

func assertAPISecurityHeaders(t *testing.T, resp *httptest.ResponseRecorder) {
	t.Helper()
	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Pragma":                 "no-cache",
		"Expires":                "0",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header().Get(name); got != want {
			t.Errorf("%s=%q, want %q (status %d)", name, got, want, resp.Code)
		}
	}
}
