package main

import (
	"fmt"
	"railgun-go/panel"
	"time"
)

func RunWorkflow() {
	for {
		fmt.Println("========================================")
		fmt.Println("railgun-go workflow")
		fmt.Println("========================================")

		for _, node := range Nodes {
			fmt.Printf("\n处理节点 %s (ID: %d)\n", node.Name, node.ID)

			processNode(node.ID)
		}

		fmt.Println("\nworkflow finished, waiting for 60 seconds")
		time.Sleep(60 * time.Second)
	}
}

func processNode(railgunID int) {
	var heartbeatErr error
	var nodeAddress string

	nodeAddress, heartbeatErr = heartbeat(railgunID)
	if heartbeatErr != nil {
		fmt.Printf("  - 心跳包流程 [Error: %v]\n", heartbeatErr)
		fmt.Printf("  - UID表更新流程 [Error: Heartbeat Error]\n")
		fmt.Printf("  - 在线IP上报流程 [Error: Heartbeat Error]\n")
		return
	}
	fmt.Printf("  - 心跳包流程 [Info: %s]\n", nodeAddress)

	uuidCount, uuidErr := fetchUUIDs(railgunID)
	if uuidErr != nil {
		fmt.Printf("  - UID表更新流程 [Error: %v]\n", uuidErr)
	} else {
		fmt.Printf("  - UID表更新流程 [Info: 同步%d个uuids数据]\n", uuidCount)
	}

	aliveIPCount, ipErr := reportOnlineIPs(railgunID)
	if ipErr != nil {
		fmt.Printf("  - 在线IP上报流程 [Error: %v]\n", ipErr)
	} else {
		fmt.Printf("  - 在线IP上报流程 [Info: 上报%d个aliveip状态]\n", aliveIPCount)
	}
}

func heartbeat(railgunID int) (string, error) {
	switch GlobalConfig.Panel.Type {
	case "xmplus":
		xmplusPanel := panel.NewXMPlusPanel(GlobalConfig.Panel.URL, GlobalConfig.Panel.Key)
		return xmplusPanel.Heartbeat(railgunID)
	case "sspanel":
		sspanel := panel.NewSSPanel(GlobalConfig.Panel.URL, GlobalConfig.Panel.Key)
		return sspanel.Heartbeat(railgunID)
	default:
		return "", fmt.Errorf("不支持的面板类型: %s", GlobalConfig.Panel.Type)
	}
}

func fetchUUIDs(railgunID int) (int, error) {
	if err := ClearUUIDs(railgunID); err != nil {
		return 0, err
	}

	var count int

	switch GlobalConfig.Panel.Type {
	case "xmplus":
		xmplusPanel := panel.NewXMPlusPanel(GlobalConfig.Panel.URL, GlobalConfig.Panel.Key)
		subscriptions, err := xmplusPanel.GetSubscriptions(railgunID)
		if err != nil {
			return 0, err
		}

		for _, sub := range subscriptions {
			ipquota := sub.IPLimit - sub.IPCount
			if err := InsertUUID(railgunID, sub.ID, sub.UUID, ipquota); err != nil {
				continue
			}
			count++
		}

	case "sspanel":
		sspanel := panel.NewSSPanel(GlobalConfig.Panel.URL, GlobalConfig.Panel.Key)
		users, err := sspanel.GetUsers(railgunID)
		if err != nil {
			return 0, err
		}

		for _, user := range users {
			ipquota := user.NodeIPLimit - user.AliveIP
			if err := InsertUUID(railgunID, user.ID, user.UUID, ipquota); err != nil {
				continue
			}
			count++
		}

	default:
		return 0, fmt.Errorf("不支持的面板类型: %s", GlobalConfig.Panel.Type)
	}

	return count, nil
}

func reportOnlineIPs(railgunID int) (int, error) {
	aliveIPs, err := GetAliveIPs(railgunID)
	if err != nil {
		return 0, err
	}

	if err := ClearAliveIPs(railgunID); err != nil {
		return 0, err
	}

	if len(aliveIPs) == 0 {
		return 0, nil
	}

	switch GlobalConfig.Panel.Type {
	case "xmplus":
		var ips []panel.XMPlusOnlineIPRequest
		for _, aliveIP := range aliveIPs {
			ips = append(ips, panel.XMPlusOnlineIPRequest{
				SubscriptionID: aliveIP.UID,
				IP:             aliveIP.IP,
			})
		}

		xmplusPanel := panel.NewXMPlusPanel(GlobalConfig.Panel.URL, GlobalConfig.Panel.Key)
		if err := xmplusPanel.ReportOnlineIPs(railgunID, ips); err != nil {
			return 0, err
		}

	case "sspanel":
		var ips []panel.SSPanelOnlineIPRequest
		for _, aliveIP := range aliveIPs {
			ips = append(ips, panel.SSPanelOnlineIPRequest{
				UserID: aliveIP.UID,
				IP:     aliveIP.IP,
			})
		}

		sspanel := panel.NewSSPanel(GlobalConfig.Panel.URL, GlobalConfig.Panel.Key)
		if err := sspanel.ReportOnlineIPs(railgunID, ips); err != nil {
			return 0, err
		}

	default:
		return 0, fmt.Errorf("不支持的面板类型: %s", GlobalConfig.Panel.Type)
	}

	return len(aliveIPs), nil
}
