package main

import (
	"fmt"
	"os"
	"os/signal"
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

	go RunWorkflow()

	go StartAPIServer()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n正在关闭程序...")
	if err := CloseDB(); err != nil {
		fmt.Printf("关闭数据库失败: %v\n", err)
	}
	fmt.Println("程序已退出")
}
