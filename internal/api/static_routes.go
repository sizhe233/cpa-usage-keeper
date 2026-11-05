package api

import (
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// registerStaticRoutes 让启动外壳和完整路由共享同一份 BasePath、资源缓存与 iframe CSP 规则。
func registerStaticRoutes(router *gin.Engine, appGroup *gin.RouterGroup, staticFS fs.FS, frameAncestorOrigins []string, basePath string, missingAPI gin.HandlerFunc) {
	var serveIndex gin.HandlerFunc
	if staticFS != nil {
		if indexFile, err := staticFS.Open("index.html"); err == nil {
			_ = indexFile.Close()
			httpFS := http.FS(staticFS)
			serveIndex = func(c *gin.Context) {
				indexHTML, err := renderIndexHTML(staticFS, basePath)
				if err != nil {
					c.Status(http.StatusNotFound)
					return
				}
				setHTMLCacheHeaders(c, frameAncestorOrigins)
				c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
			}
			serveAsset := func(c *gin.Context) {
				assetPath := "assets/" + strings.TrimPrefix(c.Param("filepath"), "/")
				if assetFile, err := staticFS.Open(assetPath); err == nil {
					_ = assetFile.Close()
					setStaticAssetCacheHeaders(c)
					c.FileFromFS(assetPath, httpFS)
					return
				}
				c.Status(http.StatusNotFound)
			}
			appGroup.GET("/", serveIndex)
			appGroup.GET("/assets/*filepath", serveAsset)
			appGroup.HEAD("/assets/*filepath", serveAsset)
		}
	}
	// 路由树已装配完成，保存只读快照；绝不通过 HandleContext 重新分派请求。
	canonicalRoutes := router.Routes()
	router.NoRoute(func(c *gin.Context) {
		if redirectRegisteredTrailingSlash(c, canonicalRoutes, basePath) {
			return
		}
		if serveIndex != nil && basePath != "" && c.Request.Method == http.MethodGet && c.Request.URL.Path == basePath {
			setHTMLCacheHeaders(c, frameAncestorOrigins)
			redirectCanonicalPath(c, http.StatusMovedPermanently, basePath+"/")
			return
		}
		requestPath, ok := stripBasePath(basePath, c.Request.URL.Path)
		if !ok {
			c.Status(http.StatusNotFound)
			return
		}
		// 探针可能携带未规范化的部署前缀；只把就绪 GET 定向到真实路由，避免 SPA 兜底误报成功。
		if c.Request.Method == http.MethodGet && requestPath == "/readyz" && c.Request.URL.Path != basePath+"/readyz" {
			setAPISecurityHeaders(c.Writer.Header())
			redirectCanonicalPath(c, http.StatusTemporaryRedirect, basePath+"/readyz")
			return
		}
		if strings.HasPrefix(requestPath, "/api/") || missingAPI != nil && requestPath == "/api" {
			if missingAPI != nil {
				missingAPI(c)
				return
			}
			c.Status(http.StatusNotFound)
			return
		}
		if serveIndex == nil {
			c.Status(http.StatusNotFound)
			return
		}
		if assetPath, ok := staticAssetPath(requestPath); ok {
			if assetFile, err := staticFS.Open(assetPath); err == nil {
				_ = assetFile.Close()
				setStaticAssetCacheHeaders(c)
				c.FileFromFS(assetPath, http.FS(staticFS))
				return
			}
		}
		serveIndex(c)
	})
}

// redirectRegisteredTrailingSlash 只移除真实 API/探针路由的一个尾斜杠，保留 Gin 的 GET 301/其他方法 307 语义。
// 调用前全局安全中间件已运行；只发送重定向，不执行 canonical handler，避免认证或写入副作用。
func redirectRegisteredTrailingSlash(c *gin.Context, routes gin.RoutesInfo, basePath string) bool {
	requestPath := c.Request.URL.Path
	if !strings.HasSuffix(requestPath, "/") || requestPath == "/" {
		return false
	}
	canonicalPath := strings.TrimSuffix(requestPath, "/")
	// 不把参数中的点段或重复斜杠交给 http.Redirect 再清理成另一个目标。
	if canonicalPath != cleanURLPath(canonicalPath) {
		return false
	}
	if !isAPIRequest(basePath, canonicalPath) && canonicalPath != basePath+"/healthz" && canonicalPath != basePath+"/readyz" {
		return false
	}
	for _, route := range routes {
		if route.Method != c.Request.Method || !matchesCanonicalRoute(route.Path, canonicalPath) {
			continue
		}
		setAPISecurityHeaders(c.Writer.Header())
		status := http.StatusTemporaryRedirect
		if c.Request.Method == http.MethodGet {
			status = http.StatusMovedPermanently
		}
		redirectCanonicalPath(c, status, canonicalPath)
		return true
	}
	return false
}

// 业务路由使用字面路径或完整 :param 段；非空参数只能匹配一段，不把静态 catch-all 当作 API。
func matchesCanonicalRoute(routePath, requestPath string) bool {
	routeSegments, requestSegments := strings.Split(routePath, "/"), strings.Split(requestPath, "/")
	if len(routeSegments) != len(requestSegments) {
		return false
	}
	for index, segment := range routeSegments {
		if strings.HasPrefix(segment, ":") && requestSegments[index] != "" {
			continue
		}
		if segment != requestSegments[index] {
			return false
		}
	}
	return true
}

func redirectCanonicalPath(c *gin.Context, status int, canonicalPath string) {
	// 构造站内 URL，不信任 Host/转发前缀；保留 OIDC 等入口的原始 query（含编码和重复键）。
	location := &url.URL{Path: canonicalPath, RawQuery: c.Request.URL.RawQuery, ForceQuery: c.Request.URL.ForceQuery}
	c.Redirect(status, location.String())
}
