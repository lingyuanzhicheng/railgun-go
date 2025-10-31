package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

//go:embed templates/*
var assets embed.FS

var dbDir = "database"

type Data struct {
	AuthKey        string `json:"authkey"`
	CDNIPSync      string `json:"cdnipsync,omitempty"`
	ProxyIPSync    string `json:"proxyipsync,omitempty"`
	ProxyHTTPSync  string `json:"proxyhttpsync,omitempty"`
	ProxySock5Sync string `json:"proxysock5sync,omitempty"`
	// 定时任务相关字段
	CronExpression        string `json:"cron_expression,omitempty"`
	UUIDSyncEnabled       bool   `json:"uuid_sync_enabled,omitempty"`
	CDNIPSyncEnabled      bool   `json:"cdnip_sync_enabled,omitempty"`
	ProxyIPSyncEnabled    bool   `json:"proxyip_sync_enabled,omitempty"`
	ProxyHTTPSyncEnabled  bool   `json:"proxyhttp_sync_enabled,omitempty"`
	ProxySock5SyncEnabled bool   `json:"proxysock5_sync_enabled,omitempty"`
}

type UUID struct {
	Uuid  string `json:"uuid"`
	Statu bool   `json:"statu"`
}

type Worker struct {
	Workers string `json:"workers"`
	Apikey  string `json:"apikey"`
	Statu   bool   `json:"statu"`
}

type IPInfo struct {
	IP   string `json:"ip"`
	Port string `json:"port"`
	Code string `json:"code"`
	ASN  string `json:"asn"`
}

type CDNIP struct {
	IP         string `json:"ip"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	City       string `json:"city"`
}

type CDNDomain struct {
	Domain string `json:"domain"`
	Option string `json:"option,omitempty"`
}

var templates *template.Template
var mu sync.Mutex

// 日志流相关变量
var clients = make(map[chan string]bool)
var clientsMutex sync.Mutex

// 定时任务相关变量
var cronManager *cron.Cron
var cronMutex sync.Mutex

// 日志流处理函数
func handleLogStream(w http.ResponseWriter, r *http.Request) {
	// 设置SSE响应头
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 创建一个新的消息通道
	messageChan := make(chan string, 10)

	// 注册客户端
	clientsMutex.Lock()
	clients[messageChan] = true
	clientsMutex.Unlock()

	// 确保在连接关闭时移除客户端
	defer func() {
		clientsMutex.Lock()
		delete(clients, messageChan)
		clientsMutex.Unlock()
		close(messageChan)
	}()

	// 发送连接成功消息
	fmt.Fprintf(w, "data: 已连接到日志流\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// 监听消息通道并发送数据
	for {
		select {
		case msg := <-messageChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

func ensureDB() error {
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return err
	}
	// create data.json if missing
	p := filepath.Join(dbDir, "data.json")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		d := Data{AuthKey: "railgun"}
		b, _ := json.MarshalIndent(d, "", "  ")
		if err := os.WriteFile(p, b, 0644); err != nil {
			return err
		}
	}
	// create uuid.json, workers.json, cdnip.json, proxyip.json, cdndomain.json, proxyhttp.json, proxysock5.json
	defaults := map[string]any{
		"uuid.json":       []any{},
		"workers.json":    []any{},
		"cdnip.json":      []any{},
		"proxyip.json":    []any{},
		"cdndomain.json":  []any{},
		"proxyhttp.json":  []any{},
		"proxysock5.json": []any{},
	}
	for name, val := range defaults {
		p := filepath.Join(dbDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			b, _ := json.MarshalIndent(val, "", "  ")
			if err := os.WriteFile(p, b, 0644); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadData() (Data, error) {
	var d Data
	b, err := os.ReadFile(filepath.Join(dbDir, "data.json"))
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, err
	}
	return d, nil
}

func saveData(d Data) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dbDir, "data.json"), b, 0644)
}

// 使用log包记录网络请求日志
func logNetworkRequest(method, url, details string, success bool) {
	status := "成功"
	if !success {
		status = "失败"
	}
	log.Printf("[%s] 网络请求 %s %s: %s (%s)",
		time.Now().Format("2006-01-02 15:04:05"),
		method,
		url,
		details,
		status)
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tmp struct {
		AuthKey string `json:"authkey"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &tmp); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	d, err := loadData()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if tmp.AuthKey != d.AuthKey {
		http.Error(w, "invalid authkey", http.StatusUnauthorized)
		return
	}

	// Set a simple session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    d.AuthKey,
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 检查session cookie
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			// 未登录，重定向到登录页面
			http.Redirect(w, r, "/auth", http.StatusFound)
			return
		}

		d, err := loadData()
		if err != nil {
			// 加载数据失败，重定向到登录页面
			http.Redirect(w, r, "/auth", http.StatusFound)
			return
		}

		if cookie.Value != d.AuthKey {
			// session无效，重定向到登录页面
			http.Redirect(w, r, "/auth", http.StatusFound)
			return
		}

		// 已登录，渲染admin.html
		renderTemplate(w, "admin.html", d)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		renderTemplate(w, "auth.html", nil)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var tmp struct {
		AuthKey string `json:"authkey"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &tmp); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	d, err := loadData()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if tmp.AuthKey != d.AuthKey {
		http.Error(w, "invalid authkey", http.StatusUnauthorized)
		return
	}
	// Set a simple session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    d.AuthKey,
		Path:     "/",
		MaxAge:   3600, // 1 hour
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/auth", http.StatusFound)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// 根目录应该直接渲染index.html，不需要认证
	renderTemplate(w, "index.html", nil)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	// basic router: /api/{action} or /api/{action}/{id}
	p := r.URL.Path[len("/api/"):]

	// 记录API请求
	logNetworkRequest(r.Method, r.URL.Path, "API请求: "+p, true)

	// 处理带ID的路径
	if strings.HasPrefix(p, "uuid/") {
		p = "uuid"
	} else if strings.HasPrefix(p, "worker/") {
		p = "worker"
	} else if strings.HasPrefix(p, "cdndomain/") {
		p = "cdndomain"
	}

	switch p {
	case "auth":
		if r.Method == http.MethodPost {
			var tmp struct {
				AuthKey string `json:"authkey"`
			}
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &tmp); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "bad json"})
				return
			}

			d, err := loadData()
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
				return
			}

			if tmp.AuthKey != d.AuthKey {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid authkey"})
				return
			}

			// Set a simple session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    d.AuthKey,
				Path:     "/",
				MaxAge:   3600, // 1 hour
				HttpOnly: true,
			})

			// Return success status
			w.WriteHeader(http.StatusOK)
		} else if r.Method == http.MethodGet {
			// 仅支持UUID参数进行鉴权
			uuid := r.URL.Query().Get("uuid")
			if uuid == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "uuid parameter is required"})
				return
			}

			// 验证UUID是否有效
			mu.Lock()
			var uuids []UUID
			uData, _ := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
			if len(uData) > 0 {
				json.Unmarshal(uData, &uuids)
			}
			mu.Unlock()

			validUUID := false
			for _, u := range uuids {
				if u.Uuid == uuid && u.Statu {
					validUUID = true
					break
				}
			}

			if !validUUID {
				http.Error(w, "invalid uuid", http.StatusUnauthorized)
				return
			}

			// 检查是否请求workers数据
			if r.URL.Query().Get("get_workers") == "true" {
				b, err := os.ReadFile(filepath.Join(dbDir, "workers.json"))
				if err != nil {
					http.Error(w, "workers not found", http.StatusNotFound)
					return
				}

				// 解析workers.json
				var workers []Worker
				if err := json.Unmarshal(b, &workers); err != nil {
					http.Error(w, "error parsing workers data", http.StatusInternalServerError)
					return
				}

				// 创建只包含workers字段且statu为true的结果
				var result []map[string]string
				for _, worker := range workers {
					if worker.Statu {
						result = append(result, map[string]string{"workers": worker.Workers})
					}
				}

				// 返回过滤后的结果
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			}

			// 检查是否请求cdnip数据
			if r.URL.Query().Get("get_cdnip") == "true" {
				b, err := os.ReadFile(filepath.Join(dbDir, "cdnip.json"))
				if err != nil {
					http.Error(w, "cdnip not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}

			// 检查是否请求cdndomain数据
			if r.URL.Query().Get("get_cdndomain") == "true" {
				b, err := os.ReadFile(filepath.Join(dbDir, "cdndomain.json"))
				if err != nil {
					http.Error(w, "cdndomain not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}

			// 检查是否请求proxyip数据
			if r.URL.Query().Get("get_proxyip") == "true" {
				b, err := os.ReadFile(filepath.Join(dbDir, "proxyip.json"))
				if err != nil {
					http.Error(w, "proxyip not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}

			// 检查是否请求proxyhttp数据
			if r.URL.Query().Get("get_proxyhttp") == "true" {
				b, err := os.ReadFile(filepath.Join(dbDir, "proxyhttp.json"))
				if err != nil {
					http.Error(w, "proxyhttp not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}

			// 检查是否请求proxysock5数据
			if r.URL.Query().Get("get_proxysock5") == "true" {
				b, err := os.ReadFile(filepath.Join(dbDir, "proxysock5.json"))
				if err != nil {
					http.Error(w, "proxysock5 not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}

			// 如果没有请求特定数据，只返回验证成功状态
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "authenticated"})
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
			return
		}
	case "data":
		// 检查session cookie
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
			return
		}

		d, err := loadData()
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
			return
		}

		if cookie.Value != d.AuthKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid session"})
			return
		}

		// return data.json
		b, err := os.ReadFile(filepath.Join(dbDir, "data.json"))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case "save_authkey":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var tmp struct {
			AuthKey string `json:"authkey"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &tmp); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		d, _ := loadData()
		d.AuthKey = tmp.AuthKey
		_ = saveData(d)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "save_cdnipsync":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var tmp struct {
			CDNIPSync string `json:"cdnipsync"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &tmp); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		d, _ := loadData()
		d.CDNIPSync = tmp.CDNIPSync
		_ = saveData(d)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "save_proxyipsync":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var tmp struct {
			ProxyIPSync string `json:"proxyipsync"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &tmp); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		d, _ := loadData()
		d.ProxyIPSync = tmp.ProxyIPSync
		_ = saveData(d)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "save_proxyhttpsync":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var tmp struct {
			ProxyHTTPSync string `json:"proxyhttpsync"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &tmp); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		d, _ := loadData()
		d.ProxyHTTPSync = tmp.ProxyHTTPSync
		_ = saveData(d)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "save_proxysock5sync":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var tmp struct {
			ProxySock5Sync string `json:"proxysock5sync"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &tmp); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		d, _ := loadData()
		d.ProxySock5Sync = tmp.ProxySock5Sync
		_ = saveData(d)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "sync_cdnip":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d, _ := loadData()
		if d.CDNIPSync == "" {
			http.Error(w, "cdnipsync url not set", http.StatusBadRequest)
			return
		}
		resp, err := http.Get(d.CDNIPSync)
		if err != nil {
			logNetworkRequest("GET", d.CDNIPSync, "CDN IP同步失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()
		logNetworkRequest("GET", d.CDNIPSync, "CDN IP同步成功", true)

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mu.Lock()
		err = os.WriteFile(filepath.Join(dbDir, "cdnip.json"), buf.Bytes(), 0644)
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case "sync_proxyip":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d, _ := loadData()
		if d.ProxyIPSync == "" {
			http.Error(w, "proxyipsync url not set", http.StatusBadRequest)
			return
		}
		resp, err := http.Get(d.ProxyIPSync)
		if err != nil {
			logNetworkRequest("GET", d.ProxyIPSync, "Proxy IP同步失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		logNetworkRequest("GET", d.ProxyIPSync, "Proxy IP同步成功", true)

		var cdnIPs []CDNIP
		if err := json.NewDecoder(resp.Body).Decode(&cdnIPs); err != nil {
			logNetworkRequest("GET", d.CDNIPSync, "解析CDN IP JSON失败: "+err.Error(), false)
			http.Error(w, "failed to parse remote JSON: "+err.Error(), http.StatusInternalServerError)
			return
		}

		jsonData, err := json.MarshalIndent(cdnIPs, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mu.Lock()
		err = os.WriteFile(filepath.Join(dbDir, "cdnip.json"), jsonData, 0644)
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "sync_proxyhttp":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d, _ := loadData()
		if d.ProxyHTTPSync == "" {
			http.Error(w, "proxyhttpsync url not set", http.StatusBadRequest)
			return
		}
		resp, err := http.Get(d.ProxyHTTPSync)
		if err != nil {
			logNetworkRequest("GET", d.ProxyHTTPSync, "Proxy HTTP同步失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		logNetworkRequest("GET", d.ProxyHTTPSync, "Proxy HTTP同步成功", true)

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 处理IP数据，转换为新的结构
		lines := strings.Split(buf.String(), "")
		var ips []IPInfo

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				ip := parts[0]
				port := parts[1]
				code := ""
				asn := ""

				if len(parts) >= 3 {
					code = parts[2]
				}
				if len(parts) >= 4 {
					asn = parts[3]
				}

				ips = append(ips, IPInfo{
					IP:   ip,
					Port: port,
					Code: code,
					ASN:  asn,
				})
			}
		}

		// 转换为JSON并保存
		jsonData, err := json.MarshalIndent(ips, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mu.Lock()
		err = os.WriteFile(filepath.Join(dbDir, "proxyhttp.json"), jsonData, 0644)
		mu.Unlock()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "sync_proxysock5":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		d, _ := loadData()
		if d.ProxySock5Sync == "" {
			http.Error(w, "proxysock5sync url not set", http.StatusBadRequest)
			return
		}
		resp, err := http.Get(d.ProxySock5Sync)
		if err != nil {
			logNetworkRequest("GET", d.ProxySock5Sync, "Proxy Sock5同步失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		logNetworkRequest("GET", d.ProxySock5Sync, "Proxy Sock5同步成功", true)

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 处理IP数据，转换为新的结构
		lines := strings.Split(buf.String(), "")
		var ips []IPInfo

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			parts := strings.Split(line, ",")
			if len(parts) >= 2 {
				ip := parts[0]
				port := parts[1]
				code := ""
				asn := ""

				if len(parts) >= 3 {
					code = parts[2]
				}
				if len(parts) >= 4 {
					asn = parts[3]
				}

				ips = append(ips, IPInfo{
					IP:   ip,
					Port: port,
					Code: code,
					ASN:  asn,
				})
			}
		}

		// 转换为JSON并保存
		jsonData, err := json.MarshalIndent(ips, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mu.Lock()
		err = os.WriteFile(filepath.Join(dbDir, "proxysock5.json"), jsonData, 0644)
		mu.Unlock()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "uuids":
		if r.Method == http.MethodGet {
			b, err := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else if r.Method == http.MethodPost {
			var u UUID
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &u); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var uuids []UUID
			b, _ := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &uuids)
			}
			uuids = append(uuids, u)
			b, _ = json.MarshalIndent(uuids, "", "  ")
			os.WriteFile(filepath.Join(dbDir, "uuid.json"), b, 0644)
			mu.Unlock()

			// 添加日志
			logNetworkRequest("POST", "/api/uuids", "添加UUID: "+u.Uuid, true)

			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "uuid":
		if r.Method == http.MethodPut {
			var u UUID
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &u); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var uuids []UUID
			b, _ := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &uuids)
			}

			for i, item := range uuids {
				if item.Uuid == u.Uuid {
					uuids[i] = u
					break
				}
			}

			b, _ = json.MarshalIndent(uuids, "", "  ")
			os.WriteFile(filepath.Join(dbDir, "uuid.json"), b, 0644)
			mu.Unlock()

			w.WriteHeader(http.StatusNoContent)
		} else if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/api/uuid/")
			if id == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var uuids []UUID
			b, _ := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &uuids)
			}

			for i, item := range uuids {
				if item.Uuid == id {
					uuids = append(uuids[:i], uuids[i+1:]...)
					break
				}
			}

			b, _ = json.MarshalIndent(uuids, "", "  ")
			os.WriteFile(filepath.Join(dbDir, "uuid.json"), b, 0644)
			mu.Unlock()

			// 添加日志
			logNetworkRequest("DELETE", "/api/uuid/"+id, "删除UUID: "+id, true)

			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "get_remote_uuids":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			WorkerURL string `json:"workerURL"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		// 查找指定的worker
		mu.Lock()
		var workers []Worker
		wData, _ := os.ReadFile(filepath.Join(dbDir, "workers.json"))
		if len(wData) > 0 {
			json.Unmarshal(wData, &workers)
		}
		mu.Unlock()

		var targetWorker *Worker
		for _, worker := range workers {
			if worker.Workers == req.WorkerURL {
				targetWorker = &worker
				break
			}
		}

		if targetWorker == nil {
			http.Error(w, "worker not found", http.StatusNotFound)
			return
		}

		// 确保URL格式正确
		url := targetWorker.Workers
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		// 向worker发送list请求
		apiURL := url + "/sync"
		reqBody, _ := json.Marshal(map[string]string{"action": "list"})

		log.Printf("准备发送请求到: %s", apiURL)
		log.Printf("请求体: %s", string(reqBody))
		log.Printf("API Key: %s", targetWorker.Apikey)

		httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(reqBody))
		if err != nil {
			logNetworkRequest("POST", apiURL, "创建请求失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		httpReq.Header.Set("Authorization", "Bearer "+targetWorker.Apikey)
		httpReq.Header.Set("Content-Type", "application/json")

		log.Printf("请求头: Authorization=%s, Content-Type=%s",
			httpReq.Header.Get("Authorization"),
			httpReq.Header.Get("Content-Type"))

		client := &http.Client{}
		resp, err := client.Do(httpReq)
		if err != nil {
			logNetworkRequest("POST", apiURL, "获取远程UUID失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		log.Printf("响应状态码: %s", resp.Status)
		log.Printf("响应头 Content-Type: %s", resp.Header.Get("Content-Type"))

		if resp.StatusCode != http.StatusOK {
			// 读取错误响应内容
			errorBody, _ := io.ReadAll(resp.Body)
			log.Printf("错误响应内容: %s", string(errorBody))
			logNetworkRequest("POST", apiURL, "获取远程UUID失败，状态码: "+resp.Status, false)
			http.Error(w, "remote server error: "+resp.Status, http.StatusInternalServerError)
			return
		}

		// 读取响应并转发给客户端
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(buf.Bytes())

		logNetworkRequest("POST", apiURL, "获取远程UUID成功", true)

	case "remote_uuid_action":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			WorkerURL string `json:"workerURL"`
			Action    string `json:"action"`
			UUID      string `json:"uuid"`
			Value     string `json:"value"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		// 验证action参数
		if req.Action != "put" && req.Action != "delete" {
			http.Error(w, "invalid action", http.StatusBadRequest)
			return
		}

		// 查找指定的worker
		mu.Lock()
		var workers []Worker
		wData, _ := os.ReadFile(filepath.Join(dbDir, "workers.json"))
		if len(wData) > 0 {
			json.Unmarshal(wData, &workers)
		}
		mu.Unlock()

		var targetWorker *Worker
		for _, worker := range workers {
			if worker.Workers == req.WorkerURL {
				targetWorker = &worker
				break
			}
		}

		if targetWorker == nil {
			http.Error(w, "worker not found", http.StatusNotFound)
			return
		}

		// 确保URL格式正确
		url := targetWorker.Workers
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		// 向worker发送操作请求
		apiURL := url + "/sync"

		// 根据操作类型构建请求体
		var reqBody []byte
		if req.Action == "put" {
			reqBody, _ = json.Marshal(map[string]string{
				"action": "put",
				"uuid":   req.UUID,
				"value":  req.Value,
			})
		} else {
			reqBody, _ = json.Marshal(map[string]string{
				"action": "delete",
				"uuid":   req.UUID,
			})
		}

		log.Printf("准备发送%s请求到: %s", req.Action, apiURL)
		log.Printf("请求体: %s", string(reqBody))
		log.Printf("API Key: %s", targetWorker.Apikey)

		httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(reqBody))
		if err != nil {
			logNetworkRequest("POST", apiURL, "创建请求失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		httpReq.Header.Set("Authorization", "Bearer "+targetWorker.Apikey)
		httpReq.Header.Set("Content-Type", "application/json")

		log.Printf("请求头: Authorization=%s, Content-Type=%s",
			httpReq.Header.Get("Authorization"),
			httpReq.Header.Get("Content-Type"))

		client := &http.Client{}
		resp, err := client.Do(httpReq)
		if err != nil {
			logNetworkRequest("POST", apiURL, "执行远程UUID操作失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		log.Printf("响应状态码: %s", resp.Status)
		log.Printf("响应头 Content-Type: %s", resp.Header.Get("Content-Type"))

		if resp.StatusCode != http.StatusOK {
			// 读取错误响应内容
			errorBody, _ := io.ReadAll(resp.Body)
			log.Printf("错误响应内容: %s", string(errorBody))
			logNetworkRequest("POST", apiURL, "执行远程UUID操作失败，状态码: "+resp.Status, false)
			http.Error(w, "remote server error: "+resp.Status, http.StatusInternalServerError)
			return
		}

		// 读取响应并转发给客户端
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(buf.Bytes())

		logNetworkRequest("POST", apiURL, "执行远程UUID操作成功", true)

	case "sync_uuid":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 检查是否指定了特定的worker
		var workerURL string
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			var tmp struct {
				WorkerURL string `json:"workerURL"`
			}
			if err := json.Unmarshal(body, &tmp); err == nil && tmp.WorkerURL != "" {
				workerURL = tmp.WorkerURL
			}
		}

		// Load workers and uuids
		mu.Lock()
		var workers []Worker
		wData, _ := os.ReadFile(filepath.Join(dbDir, "workers.json"))
		if len(wData) > 0 {
			json.Unmarshal(wData, &workers)
		}

		var uuids []UUID
		uData, _ := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
		if len(uData) > 0 {
			json.Unmarshal(uData, &uuids)
		}
		mu.Unlock()

		// 确定要同步的worker列表
		var targetWorkers []Worker
		if workerURL != "" {
			// 只同步指定的worker
			for _, worker := range workers {
				if worker.Workers == workerURL {
					targetWorkers = append(targetWorkers, worker)
					break
				}
			}
		} else {
			// 同步所有worker
			targetWorkers = workers
		}

		// Sync each worker's KV with uuids
		for _, worker := range targetWorkers {
			// 只同步启用的worker
			if !worker.Statu {
				continue
			}

			// Send to Worker /sync endpoint
			// 确保URL格式正确
			url := worker.Workers
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "https://" + url
			}

			// 直接发送uuid.json数据到/sync端点
			apiURL := url + "/sync"

			// 读取uuid.json文件内容
			uuidData, err := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
			if err != nil {
				log.Printf("Failed to read uuid.json: %v", err)
				continue
			}

			// 解析uuid.json数据
			var uuids []UUID
			if len(uuidData) > 0 {
				if err := json.Unmarshal(uuidData, &uuids); err != nil {
					log.Printf("Failed to parse uuid.json: %v", err)
					continue
				}
			}

			// 按照API案例格式构建请求数据
			syncData := map[string]interface{}{
				"action": "sync",
				"data":   uuids,
			}
			jsonData, err := json.Marshal(syncData)
			if err != nil {
				log.Printf("Failed to marshal sync data: %v", err)
				continue
			}

			req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("Failed to create request for worker %s: %v", worker.Workers, err)
				continue
			}

			req.Header.Set("Authorization", "Bearer "+worker.Apikey)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				logNetworkRequest("POST", apiURL, "同步UUID到Worker失败: "+err.Error(), false)
				continue
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				logNetworkRequest("POST", apiURL, "同步UUID到Worker失败，状态码: "+resp.Status, false)
			} else {
				logNetworkRequest("POST", apiURL, "同步UUID到Worker成功", true)
			}
		}

		// 添加日志
		syncMessage := "同步UUID到Worker"
		if workerURL != "" {
			syncMessage += " (" + workerURL + ")"
		}
		logNetworkRequest("POST", "/api/sync", syncMessage, true)

		w.WriteHeader(http.StatusNoContent)
	case "workers":
		if r.Method == http.MethodGet {
			b, err := os.ReadFile(filepath.Join(dbDir, "workers.json"))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else if r.Method == http.MethodPost {
			var worker Worker
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &worker); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var workers []Worker
			b, _ := os.ReadFile(filepath.Join(dbDir, "workers.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &workers)
			}
			workers = append(workers, worker)
			b, _ = json.MarshalIndent(workers, "", "  ")
			os.WriteFile(filepath.Join(dbDir, "workers.json"), b, 0644)
			mu.Unlock()

			// 添加日志
			logNetworkRequest("POST", "/api/workers", "添加Worker: "+worker.Workers, true)

			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "worker":
		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/api/worker/")
			if id == "" {
				http.Error(w, "missing id", http.StatusBadRequest)
				return
			}

			idx, err := strconv.Atoi(id)
			if err != nil {
				http.Error(w, "invalid id", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var workers []Worker
			b, _ := os.ReadFile(filepath.Join(dbDir, "workers.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &workers)
			}

			var deletedWorker string
			if idx >= 0 && idx < len(workers) {
				deletedWorker = workers[idx].Workers
				workers = append(workers[:idx], workers[idx+1:]...)
				b, _ = json.MarshalIndent(workers, "", "  ")
				os.WriteFile(filepath.Join(dbDir, "workers.json"), b, 0644)
			}
			mu.Unlock()

			// 添加日志
			if deletedWorker != "" {
				logNetworkRequest("DELETE", "/api/worker/"+id, "删除Worker: "+deletedWorker, true)
			}

			w.WriteHeader(http.StatusNoContent)
		} else if r.Method == http.MethodPut {
			// 更新Worker状态
			var tmp struct {
				Index int  `json:"index"`
				Statu bool `json:"statu"`
			}
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &tmp); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var workers []Worker
			b, _ := os.ReadFile(filepath.Join(dbDir, "workers.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &workers)
			}

			var updatedWorker string
			if tmp.Index >= 0 && tmp.Index < len(workers) {
				updatedWorker = workers[tmp.Index].Workers
				workers[tmp.Index].Statu = tmp.Statu
				b, _ = json.MarshalIndent(workers, "", "  ")
				os.WriteFile(filepath.Join(dbDir, "workers.json"), b, 0644)
			}
			mu.Unlock()

			// 添加日志
			if updatedWorker != "" {
				statusText := "禁用"
				if tmp.Statu {
					statusText = "启用"
				}
				logNetworkRequest("PUT", "/api/worker", statusText+"Worker: "+updatedWorker, true)
			}

			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "cdnip":
		if r.Method == http.MethodGet {
			b, err := os.ReadFile(filepath.Join(dbDir, "cdnip.json"))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "proxyip":
		if r.Method == http.MethodGet {
			b, err := os.ReadFile(filepath.Join(dbDir, "proxyip.json"))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "proxyhttp":
		if r.Method == http.MethodGet {
			b, err := os.ReadFile(filepath.Join(dbDir, "proxyhttp.json"))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "proxysock5":
		if r.Method == http.MethodGet {
			b, err := os.ReadFile(filepath.Join(dbDir, "proxysock5.json"))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "cdndomains":
		if r.Method == http.MethodGet {
			b, err := os.ReadFile(filepath.Join(dbDir, "cdndomain.json"))
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		} else if r.Method == http.MethodPost {
			var d CDNDomain
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &d); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var domains []CDNDomain
			b, _ := os.ReadFile(filepath.Join(dbDir, "cdndomain.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &domains)
			}
			domains = append(domains, d)
			b, _ = json.MarshalIndent(domains, "", "  ")
			os.WriteFile(filepath.Join(dbDir, "cdndomain.json"), b, 0644)
			mu.Unlock()

			// 添加日志
			logNetworkRequest("POST", "/api/cdndomains", "添加CDN域名: "+d.Domain, true)

			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "cdndomain":
		if r.Method == http.MethodDelete {
			id := strings.TrimPrefix(r.URL.Path, "/api/cdndomain/")
			if id == "" {
				http.Error(w, "missing domain", http.StatusBadRequest)
				return
			}

			mu.Lock()
			var domains []CDNDomain
			b, _ := os.ReadFile(filepath.Join(dbDir, "cdndomain.json"))
			if len(b) > 0 {
				json.Unmarshal(b, &domains)
			}

			var deletedDomain string
			for i, item := range domains {
				if item.Domain == id {
					deletedDomain = item.Domain
					domains = append(domains[:i], domains[i+1:]...)
					break
				}
			}

			if deletedDomain != "" {
				b, _ = json.MarshalIndent(domains, "", "  ")
				os.WriteFile(filepath.Join(dbDir, "cdndomain.json"), b, 0644)
			}
			mu.Unlock()

			// 添加日志
			if deletedDomain != "" {
				logNetworkRequest("DELETE", "/api/cdndomain/"+id, "删除CDN域名: "+deletedDomain, true)
			}

			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "download_file":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			URL      string `json:"url"`
			FileName string `json:"fileName"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		if req.URL == "" || req.FileName == "" {
			http.Error(w, "url and fileName are required", http.StatusBadRequest)
			return
		}

		resp, err := http.Get(req.URL)
		if err != nil {
			logNetworkRequest("GET", req.URL, "下载文件失败: "+err.Error(), false)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		logNetworkRequest("GET", req.URL, "下载文件成功", true)

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, resp.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		mu.Lock()
		err = os.WriteFile(filepath.Join(dbDir, req.FileName), buf.Bytes(), 0644)
		mu.Unlock()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "save_cron_settings":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var tmp struct {
			CronExpression        string `json:"cron_expression"`
			UUIDSyncEnabled       bool   `json:"uuid_sync_enabled"`
			CDNIPSyncEnabled      bool   `json:"cdnip_sync_enabled"`
			ProxyIPSyncEnabled    bool   `json:"proxyip_sync_enabled"`
			ProxyHTTPSyncEnabled  bool   `json:"proxyhttp_sync_enabled"`
			ProxySock5SyncEnabled bool   `json:"proxysock5_sync_enabled"`
		}
		body, _ := io.ReadAll(r.Body)
		log.Printf("接收到的定时任务设置请求: %s", string(body))
		if err := json.Unmarshal(body, &tmp); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		log.Printf("解析后的定时任务设置: %+v", tmp)

		mu.Lock()
		d, _ := loadData()

		// 如果只更新cron表达式，则只更新表达式
		if tmp.CronExpression != "" && tmp.UUIDSyncEnabled == d.UUIDSyncEnabled &&
			tmp.CDNIPSyncEnabled == d.CDNIPSyncEnabled &&
			tmp.ProxyIPSyncEnabled == d.ProxyIPSyncEnabled &&
			tmp.ProxyHTTPSyncEnabled == d.ProxyHTTPSyncEnabled &&
			tmp.ProxySock5SyncEnabled == d.ProxySock5SyncEnabled {
			d.CronExpression = tmp.CronExpression
		} else {
			// 否则更新所有设置
			d.CronExpression = tmp.CronExpression
			d.UUIDSyncEnabled = tmp.UUIDSyncEnabled
			d.CDNIPSyncEnabled = tmp.CDNIPSyncEnabled
			d.ProxyIPSyncEnabled = tmp.ProxyIPSyncEnabled
			d.ProxyHTTPSyncEnabled = tmp.ProxyHTTPSyncEnabled
			d.ProxySock5SyncEnabled = tmp.ProxySock5SyncEnabled
		}

		_ = saveData(d)
		mu.Unlock()

		// 更新定时任务
		updateCronJob(d)

		w.WriteHeader(http.StatusNoContent)
	case "get_cron_next":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		d, err := loadData()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		if d.CronExpression == "" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"next_run": "未启用", "next_run_timestamp": 0}`))
			return
		}

		// 解析cron表达式并计算下次执行时间
		spec := d.CronExpression

		// 支持6位格式 (秒 分 时 日 月 周)
		// 如果是5位格式，添加秒字段
		parts := strings.Fields(spec)

		if len(parts) == 5 {
			spec = "0 " + spec
		} else if len(parts) != 6 {
			log.Printf("cron表达式格式错误: %s", spec)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"next_run": "表达式格式错误", "next_run_timestamp": 0}`))
			return
		}

		// 创建cron解析器
		c := cron.New(cron.WithParser(cron.NewParser(
			cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
		)))

		// 启动cron实例
		c.Start()

		entryID, err := c.AddFunc(spec, func() {})
		if err != nil {
			log.Printf("添加cron任务失败: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"next_run": "表达式错误", "next_run_timestamp": 0}`))
			return
		}

		entry := c.Entry(entryID)
		nextRun := entry.Next
		nextRunStr := nextRun.Format("2006-01-02 15:04:05")
		nextRunTimestamp := nextRun.Unix()

		log.Printf("当前时间: %s, 下次执行时间: %s", time.Now().Format("2006-01-02 15:04:05"), nextRunStr)

		// 停止cron实例
		c.Stop()

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"next_run": "%s", "next_run_timestamp": %d}`, nextRunStr, nextRunTimestamp)))
	default:
		http.Error(w, "unknown api", http.StatusNotFound)
	}
}

// 更新定时任务
func updateCronJob(d Data) {
	cronMutex.Lock()
	defer cronMutex.Unlock()

	// 停止现有的定时任务
	if cronManager != nil {
		cronManager.Stop()
		cronManager = nil
	}

	// 如果cron表达式为空，则直接返回
	if d.CronExpression == "" {
		log.Printf("定时任务表达式为空")
		return
	}

	// 创建新的定时任务管理器
	cronManager = cron.New(cron.WithSeconds())

	// 解析cron表达式
	spec := d.CronExpression
	// 支持6位格式 (秒 分 时 日 月 周)
	parts := strings.Fields(spec)

	if len(parts) == 5 {
		// 如果是5位格式，添加秒字段
		spec = "0 " + spec
	} else if len(parts) != 6 {
		log.Printf("cron表达式格式错误: %s", spec)
		return
	}

	// 创建cron解析器，确保正确处理间隔格式
	cronManager = cron.New(cron.WithParser(cron.NewParser(
		cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
	)))

	// 添加定时任务
	_, err := cronManager.AddFunc(spec, func() {
		log.Printf("定时任务开始执行 - %s", time.Now().Format("2006-01-02 15:04:05"))

		// 每次执行时重新加载数据，获取最新的开关状态
		currentData, err := loadData()
		if err != nil {
			log.Printf("加载数据失败: %v", err)
			return
		}

		// 执行各项同步任务
		if currentData.UUIDSyncEnabled {
			log.Printf("执行UUID同步任务")
			syncUUIDTask()
		}
		if currentData.CDNIPSyncEnabled {
			log.Printf("执行CDNIP同步任务")
			syncCDNIPTask(currentData)
		}
		if currentData.ProxyIPSyncEnabled {
			log.Printf("执行ProxyIP同步任务")
			syncProxyIPTask(currentData)
		}
		if currentData.ProxyHTTPSyncEnabled {
			log.Printf("执行ProxyHTTP同步任务")
			syncProxyHTTPTask(currentData)
		}
		if currentData.ProxySock5SyncEnabled {
			log.Printf("执行ProxySock5同步任务")
			syncProxySock5Task(currentData)
		}

		log.Printf("定时任务执行完成 - %s", time.Now().Format("2006-01-02 15:04:05"))

		// 计算并记录下次执行时间
		if cronManager != nil {
			entries := cronManager.Entries()
			if len(entries) > 0 {
				nextRun := entries[0].Next
				log.Printf("下次执行时间: %s", nextRun.Format("2006-01-02 15:04:05"))
			}
		}
	})

	if err != nil {
		log.Printf("添加定时任务失败: %v", err)
		return
	}

	// 启动定时任务
	cronManager.Start()
	log.Printf("定时任务已启动，表达式: %s", spec)

	// 计算并记录下次执行时间
	entries := cronManager.Entries()
	if len(entries) > 0 {
		nextRun := entries[0].Next
		log.Printf("当前时间: %s, 下次执行时间: %s", time.Now().Format("2006-01-02 15:04:05"), nextRun.Format("2006-01-02 15:04:05"))
	}
}

// UUID同步任务
func syncUUIDTask() {
	// 加载workers和uuids
	mu.Lock()
	var workers []Worker
	wData, _ := os.ReadFile(filepath.Join(dbDir, "workers.json"))
	if len(wData) > 0 {
		json.Unmarshal(wData, &workers)
	}

	var uuids []UUID
	uData, _ := os.ReadFile(filepath.Join(dbDir, "uuid.json"))
	if len(uData) > 0 {
		json.Unmarshal(uData, &uuids)
	}
	mu.Unlock()

	// 同步每个worker的KV与uuids
	for _, worker := range workers {
		// 只同步启用的worker
		if !worker.Statu {
			continue
		}

		// 确保URL格式正确
		url := worker.Workers
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		// 直接发送uuid.json数据到/sync端点
		apiURL := url + "/sync"

		// 按照API案例格式构建请求数据
		syncData := map[string]interface{}{
			"action": "sync",
			"data":   uuids,
		}
		jsonData, err := json.Marshal(syncData)
		if err != nil {
			log.Printf("Failed to marshal sync data: %v", err)
			continue
		}

		req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("Failed to create request for worker %s: %v", worker.Workers, err)
			continue
		}

		req.Header.Set("Authorization", "Bearer "+worker.Apikey)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("同步UUID到Worker失败: %v", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("同步UUID到Worker失败，状态码: %s", resp.Status)
		} else {
			log.Printf("定时任务: 同步UUID到Worker成功")
		}
	}
}

// CDNIP同步任务
func syncCDNIPTask(d Data) {
	if d.CDNIPSync == "" {
		log.Printf("定时任务: CDNIP同步URL未设置")
		return
	}

	syncProxyFile(d.CDNIPSync, "cdnip.json", "CDN IP")
}

// ProxyIP同步任务
func syncProxyIPTask(d Data) {
	if d.ProxyIPSync == "" {
		log.Printf("定时任务: ProxyIP同步URL未设置")
		return
	}

	syncProxyFile(d.ProxyIPSync, "proxyip.json", "Proxy IP")
}

// ProxyHTTP同步任务
func syncProxyHTTPTask(d Data) {
	if d.ProxyHTTPSync == "" {
		log.Printf("定时任务: ProxyHTTP同步URL未设置")
		return
	}

	syncProxyFile(d.ProxyHTTPSync, "proxyhttp.json", "Proxy HTTP")
}

// ProxySock5同步任务
func syncProxySock5Task(d Data) {
	if d.ProxySock5Sync == "" {
		log.Printf("定时任务: ProxySock5同步URL未设置")
		return
	}

	syncProxyFile(d.ProxySock5Sync, "proxysock5.json", "Proxy Sock5")
}

// 通用代理文件同步函数
func syncProxyFile(url, fileName, fileType string) {
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("定时任务: %s同步失败: %v", fileType, err)
		return
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		log.Printf("定时任务: 读取%s响应失败: %v", fileType, err)
		return
	}

	// 直接保存文件内容
	mu.Lock()
	err = os.WriteFile(filepath.Join(dbDir, fileName), buf.Bytes(), 0644)
	mu.Unlock()

	if err != nil {
		log.Printf("定时任务: %s保存失败: %v", fileType, err)
		return
	}

	log.Printf("定时任务: %s同步成功", fileType)
}

func main() {
	if err := ensureDB(); err != nil {
		log.Fatalf("ensure db: %v", err)
	}
	t, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}
	templates = t

	// 创建日志管道
	logPipe := make(chan string, 100)
	go func() {
		for msg := range logPipe {
			// 将日志消息发送给所有连接的客户端
			clientsMutex.Lock()
			for client := range clients {
				select {
				case client <- msg:
				default:
					// 客户端缓冲区已满，跳过
				}
			}
			clientsMutex.Unlock()
		}
	}()

	// 重定向标准输出和错误输出到我们的日志管道
	pr, pw, _ := os.Pipe()
	go func() {
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			logPipe <- scanner.Text()
		}
	}()

	// 创建自定义日志写入器
	logWriter := io.MultiWriter(os.Stdout, pw)
	log.SetOutput(logWriter)

	// 初始化定时任务
	d, err := loadData()
	if err != nil {
		log.Printf("加载数据失败: %v", err)
	} else {
		updateCronJob(d)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/auth", authHandler)
	mux.HandleFunc("/admin", adminHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/api/", apiHandler)
	mux.HandleFunc("/api/logs/stream", handleLogStream)

	// 添加静态文件服务
	staticDir := "./static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		os.MkdirAll(staticDir, 0755)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	addr := ":8080"
	fmt.Println("listening on", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}