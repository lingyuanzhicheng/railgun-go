package main

import (
	"fmt"
	"os"
	"os/signal"
	"railgun-go/proxyip"
	"syscall"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("railgun-go - API中继项目")
	fmt.Println("========================================")

	fmt.Println("开始加载配置文件...")
	if err := LoadConfig(); err != nil {
		fmt.Printf("配置加载失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("开始初始化数据库...")
	if err := InitDB(); err != nil {
		fmt.Printf("数据库初始化失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("开始初始化proxyip...")
	if GlobalConfig.ProxyIP.Type == "remote" && GlobalConfig.ProxyIP.Remote != "" {
		fmt.Println("开始从远程拉取proxyip数据库...")
		if err := proxyip.SyncRemoteProxyIP(GlobalConfig.ProxyIP.Remote); err != nil {
			fmt.Printf("远程proxyip同步失败: %v\n", err)
		}
	}

	if err := proxyip.InitDB(GlobalConfig.ProxyIP.Data); err != nil {
		fmt.Printf("proxyip初始化失败: %v\n", err)
		os.Exit(1)
	}

	if GlobalConfig.ProxyIP.Data == "cache" {
		if err := proxyip.InitCacheFromSQLite(); err != nil {
			fmt.Printf("proxyip缓存初始化失败: %v\n", err)
		}
	}

	if GlobalConfig.ProxyIP.Type == "local" && GlobalConfig.ProxyIP.Check.URL != "" && GlobalConfig.ProxyIP.Check.Key != "" {
		if err := proxyip.StartCron(GlobalConfig.ProxyIP.Cron, GlobalConfig.ProxyIP.Type, GlobalConfig.ProxyIP.Data, GlobalConfig.ProxyIP.Check.URL, GlobalConfig.ProxyIP.Check.Key, GlobalConfig.ProxyIP.Check.Mode, GlobalConfig.ProxyIP.Remote); err != nil {
			fmt.Printf("proxyip定时任务启动失败: %v\n", err)
		}
	} else if GlobalConfig.ProxyIP.Type == "remote" && GlobalConfig.ProxyIP.Remote != "" {
		if err := proxyip.StartCron(GlobalConfig.ProxyIP.Cron, GlobalConfig.ProxyIP.Type, GlobalConfig.ProxyIP.Data, "", "", "", GlobalConfig.ProxyIP.Remote); err != nil {
			fmt.Printf("proxyip定时任务启动失败: %v\n", err)
		}
	}

	go RunWorkflow()

	go StartAPIServer()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n正在关闭程序...")
	if err := CloseDB(); err != nil {
		fmt.Printf("关闭数据库失败: %v\n", err)
	}
	if err := proxyip.Close(); err != nil {
		fmt.Printf("关闭proxyip失败: %v\n", err)
	}
	fmt.Println("程序已退出")
}
