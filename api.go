package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
)

type APIRequest struct {
	UUID string `json:"uuid"`
	IP   string `json:"ip"`
}

type APIResponse struct {
	Auth bool `json:"auth"`
}

func StartAPIServer() {
	rootPath := path.Join(GlobalConfig.Base, "/")
	apiPath := path.Join(GlobalConfig.Base, "api") + "/"

	http.HandleFunc(rootPath, handleRootRequest)
	http.HandleFunc(apiPath, handleAPIRequest)

	port := fmt.Sprintf(":%d", GlobalConfig.Port)
	fmt.Printf("API服务器启动，监听端口 %d，基础路径: %s\n", GlobalConfig.Port, GlobalConfig.Base)
	if err := http.ListenAndServe(port, nil); err != nil {
		fmt.Printf("API服务器启动失败: %v\n", err)
	}
}

func handleRootRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("railgun-go is running"))
}

func handleAPIRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		apiPath := path.Join(GlobalConfig.Base, "api")
		if r.URL.Path == apiPath || r.URL.Path == apiPath+"/" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("railgun-go api service"))
			return
		}
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	query := r.URL.Query()
	authKey := query.Get("key")

	if authKey != GlobalConfig.AuthKey {
		fmt.Printf("API请求验证失败 - authkey不匹配\n")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	apiPath := path.Join(GlobalConfig.Base, "api") + "/"
	requestPath := strings.TrimPrefix(r.URL.Path, apiPath)
	railgunIDStr := strings.TrimSuffix(requestPath, "/")

	railgunID, err := strconv.Atoi(railgunIDStr)
	if err != nil {
		fmt.Printf("API请求验证失败 - 节点ID格式错误\n")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	var req APIRequest
	if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
		fmt.Printf("API请求验证失败 - 请求体解析错误\n")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	uuidRecord, err := GetUUID(railgunID, req.UUID)
	if err != nil {
		fmt.Printf("API请求验证失败 - 查询uuid记录错误: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	if uuidRecord == nil {
		fmt.Printf("API请求验证失败 - 节点 %d 不存在uuid %s\n", railgunID, req.UUID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	aliveIPCount, err := GetAliveIPCount(railgunID, uuidRecord.UID)
	if err != nil {
		fmt.Printf("API请求验证失败 - 查询在线IP数量错误: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	ipquota := uuidRecord.IPQuota - aliveIPCount
	if ipquota <= 0 {
		fmt.Printf("API请求验证失败 - 用户 %d 的ipquota不足 (剩余: %d)\n", uuidRecord.UID, ipquota)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	if err := InsertAliveIP(railgunID, uuidRecord.UID, req.IP); err != nil {
		fmt.Printf("API请求验证失败 - 插入在线IP记录错误: %v\n", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(APIResponse{Auth: false})
		return
	}

	fmt.Printf("API请求验证成功 - 节点 %d, 用户 %d, uuid %s, ip %s (剩余ipquota: %d)\n",
		railgunID, uuidRecord.UID, req.UUID, req.IP, ipquota-1)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{Auth: true})
}
