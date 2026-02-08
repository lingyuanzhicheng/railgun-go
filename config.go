package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	AuthKey string      `json:"authkey"`
	Port    int         `json:"port"`
	Base    string      `json:"base"`
	Data    string      `json:"data"`
	Panel   PanelConfig `json:"panel"`
}

type PanelConfig struct {
	Type string `json:"type"`
	URL  string `json:"url"`
	Key  string `json:"key"`
}

type Node struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Requests int    `json:"requests"`
}

var (
	GlobalConfig *Config
	Nodes        []Node
)

func LoadConfig() error {
	configPath := filepath.Join("config", "config.json")
	nodesPath := filepath.Join("config", "railgun.json")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("配置文件 %s 不存在", configPath)
	}

	if _, err := os.Stat(nodesPath); os.IsNotExist(err) {
		return fmt.Errorf("节点信息文件 %s 不存在", nodesPath)
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	if unmarshalErr := json.Unmarshal(configData, &GlobalConfig); unmarshalErr != nil {
		return fmt.Errorf("解析配置文件失败: %v", unmarshalErr)
	}

	nodesData, err := os.ReadFile(nodesPath)
	if err != nil {
		return fmt.Errorf("读取节点信息文件失败: %v", err)
	}

	if unmarshalErr := json.Unmarshal(nodesData, &Nodes); unmarshalErr != nil {
		return fmt.Errorf("解析节点信息文件失败: %v", unmarshalErr)
	}

	fmt.Println("配置文件加载成功")
	fmt.Printf("面板类型: %s, 面板URL: %s\n", GlobalConfig.Panel.Type, GlobalConfig.Panel.URL)
	fmt.Printf("加载了 %d 个节点\n", len(Nodes))

	return nil
}
