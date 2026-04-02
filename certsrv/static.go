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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, nil); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func serveHTMLWithData(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
