package certsrv

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed static/*.html
var staticFS embed.FS

// staticFiles 暴露给 http.FileServer 使用
var staticFiles = staticFS

// templates 解析所有 HTML 模板
var templates = template.Must(template.ParseFS(staticFS, "static/*.html"))

func serveHTML(w http.ResponseWriter, name string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if err := templates.ExecuteTemplate(w, name, nil); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func serveHTMLWithData(w http.ResponseWriter, name string, data any) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store") // 动态页面禁止缓存，防止浏览器缓存旧状态
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
