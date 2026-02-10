package proxyip

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"railgun-go/proxyip/database"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

type CheckResponse struct {
	Success bool `json:"success"`
}

var (
	cronJob    *cron.Cron
	configType string
	dataType   string
)

func InitCacheFromSQLite() error {
	tempSQLiteDB := database.NewSQLiteDB()
	if err := tempSQLiteDB.Init(); err != nil {
		return fmt.Errorf("初始化SQLite数据库失败: %v", err)
	}
	defer tempSQLiteDB.Close()

	proxyIPs, err := tempSQLiteDB.GetAll()
	if err != nil {
		return fmt.Errorf("获取proxyip数据失败: %v", err)
	}

	for _, proxyIP := range proxyIPs {
		if err := Insert(proxyIP.IP, proxyIP.Port, proxyIP.Code, proxyIP.Org, proxyIP.Status); err != nil {
			fmt.Printf("缓存proxyip失败: %v\n", err)
		}
	}

	fmt.Printf("已缓存 %d 条proxyip记录\n", len(proxyIPs))
	return nil
}

func StartCron(cronExpr, configTypeParam, dataTypeParam, checkURL, checkKey, checkMode, remoteURL string) error {
	configType = configTypeParam
	dataType = dataTypeParam

	parts := strings.Split(cronExpr, " ")
	if len(parts) != 5 {
		return fmt.Errorf("cron表达式格式错误，只支持5字段格式（分 时 日 月 周），当前为%d字段", len(parts))
	}

	c := cron.New()

	if configType == "local" && checkURL != "" && checkKey != "" {
		_, err := c.AddFunc(cronExpr, func() {
			if err := checkProxyIPs(checkURL, checkKey, checkMode); err != nil {
				fmt.Printf("proxyip检查失败: %v\n", err)
			}
		})
		if err != nil {
			return fmt.Errorf("添加定时任务失败: %v", err)
		}
	} else if configType == "remote" {
		_, err := c.AddFunc(cronExpr, func() {
			if err := syncRemoteProxyIP(remoteURL); err != nil {
				fmt.Printf("proxyip远程同步失败: %v\n", err)
			}
		})
		if err != nil {
			return fmt.Errorf("添加定时任务失败: %v", err)
		}
	}

	c.Start()
	cronJob = c
	return nil
}

func StopCron() {
	if cronJob != nil {
		cronJob.Stop()
		fmt.Println("proxyip定时任务已停止")
	}
}

func checkProxyIPs(checkURL, checkKey, checkMode string) error {
	var proxyIPs []ProxyIP
	var err error

	if checkMode == "valid" {
		proxyIPs, err = GetValid()
		if err != nil {
			return fmt.Errorf("获取有效proxyip失败: %v", err)
		}
	} else {
		proxyIPs, err = GetAll()
		if err != nil {
			return fmt.Errorf("获取所有proxyip失败: %v", err)
		}
	}

	fmt.Printf("开始检查 %d 个proxyip\n", len(proxyIPs))

	checkedCount := 0
	for _, proxyIP := range proxyIPs {
		valid, err := checkSingleProxyIP(checkURL, checkKey, proxyIP.IP, proxyIP.Port)
		if err != nil {
			fmt.Printf("proxyip %s:%s 检查故障，%v\n", proxyIP.IP, proxyIP.Port, err)
			continue
		}
		checkedCount++

		if checkMode == "valid" {
			if !valid && proxyIP.Status == "valid" {
				if err := UpdateStatus(proxyIP.IP, proxyIP.Port, "invalid"); err != nil {
					fmt.Printf("proxyip %s:%s 状态更新失败，%v\n", proxyIP.IP, proxyIP.Port, err)
				} else {
					fmt.Printf("proxyip %s:%s 检查无效，状态更改invalid\n", proxyIP.IP, proxyIP.Port)
				}
			} else if valid && proxyIP.Status == "valid" {
				fmt.Printf("proxyip %s:%s 检查通过，状态保持valid\n", proxyIP.IP, proxyIP.Port)
			}
		} else {
			newStatus := "invalid"
			if valid {
				newStatus = "valid"
			}
			if err := UpdateStatus(proxyIP.IP, proxyIP.Port, newStatus); err != nil {
				fmt.Printf("proxyip %s:%s 状态更新失败，%v\n", proxyIP.IP, proxyIP.Port, err)
			} else {
				if newStatus == "valid" {
					fmt.Printf("proxyip %s:%s 检查通过，状态更改valid\n", proxyIP.IP, proxyIP.Port)
				} else {
					fmt.Printf("proxyip %s:%s 检查无效，状态更改invalid\n", proxyIP.IP, proxyIP.Port)
				}
			}
		}
	}

	fmt.Printf("proxyip检查任务完成，共检查 %d 个proxyip\n", checkedCount)

	if err := reloadDatabase(); err != nil {
		return fmt.Errorf("重载数据库失败: %v", err)
	}

	return nil
}

func checkSingleProxyIP(checkURL, checkKey, ip, port string) (bool, error) {
	url := fmt.Sprintf("%s/check?proxyip=%s:%s&token=%s", checkURL, ip, port, checkKey)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return false, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("读取响应失败: %v", err)
	}

	var checkResp CheckResponse
	if err := json.Unmarshal(body, &checkResp); err != nil {
		return false, fmt.Errorf("解析响应失败: %v", err)
	}

	return checkResp.Success, nil
}

func reloadDatabase() error {
	fmt.Println("开始重载数据库...")

	if err := CloseDB(); err != nil {
		return fmt.Errorf("关闭数据库失败: %v", err)
	}

	if err := InitDB(dataType); err != nil {
		return fmt.Errorf("重新初始化数据库失败: %v", err)
	}

	if dataType == "cache" {
		if err := InitCacheFromSQLite(); err != nil {
			return fmt.Errorf("重新初始化缓存失败: %v", err)
		}
	}

	fmt.Println("数据库重载完成")
	return nil
}

func syncRemoteProxyIP(remoteURL string) error {
	if remoteURL == "" {
		return fmt.Errorf("未设置远程proxyip地址")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(remoteURL)
	if err != nil {
		return fmt.Errorf("下载远程proxyip失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取远程proxyip数据失败: %v", err)
	}

	localPath := filepath.Join("config", "proxyip.db")
	if err := os.WriteFile(localPath, body, 0644); err != nil {
		return fmt.Errorf("写入本地proxyip文件失败: %v", err)
	}

	fmt.Println("远程proxyip同步完成")

	if err := reloadDatabase(); err != nil {
		return fmt.Errorf("重载数据库失败: %v", err)
	}

	return nil
}

func SyncRemoteProxyIP(remoteURL string) error {
	if remoteURL == "" {
		return fmt.Errorf("未设置远程proxyip地址")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(remoteURL)
	if err != nil {
		return fmt.Errorf("下载远程proxyip失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取远程proxyip数据失败: %v", err)
	}

	localPath := filepath.Join("config", "proxyip.db")
	if err := os.WriteFile(localPath, body, 0644); err != nil {
		return fmt.Errorf("写入本地proxyip文件失败: %v", err)
	}

	fmt.Println("远程proxyip同步完成")
	return nil
}

func GetRandomProxyIP() (string, error) {
	proxyIPs, err := GetValid()
	if err != nil {
		return "", fmt.Errorf("获取有效proxyip失败: %v", err)
	}

	if len(proxyIPs) == 0 {
		return "", fmt.Errorf("没有可用的有效proxyip")
	}

	randomIndex := time.Now().UnixNano() % int64(len(proxyIPs))
	proxyIP := proxyIPs[randomIndex]

	return fmt.Sprintf("%s:%s", proxyIP.IP, proxyIP.Port), nil
}

func GetProxyIPsByCode(code string) ([]string, error) {
	proxyIPs, err := GetByCode(code)
	if err != nil {
		return nil, fmt.Errorf("根据code获取proxyip失败: %v", err)
	}

	var result []string
	for _, proxyIP := range proxyIPs {
		result = append(result, fmt.Sprintf("%s:%s", proxyIP.IP, proxyIP.Port))
	}

	return result, nil
}

func GetRandomProxyIPByCode(code string) (string, error) {
	proxyIPs, err := GetByCode(code)
	if err != nil {
		return "", fmt.Errorf("根据code获取proxyip失败: %v", err)
	}

	var validProxyIPs []string
	for _, proxyIP := range proxyIPs {
		if proxyIP.Status == "valid" {
			validProxyIPs = append(validProxyIPs, fmt.Sprintf("%s:%s", proxyIP.IP, proxyIP.Port))
		}
	}

	if len(validProxyIPs) == 0 {
		return "", fmt.Errorf("没有可用的有效proxyip")
	}

	randomIndex := time.Now().UnixNano() % int64(len(validProxyIPs))
	return validProxyIPs[randomIndex], nil
}

func Close() error {
	StopCron()
	return CloseDB()
}
