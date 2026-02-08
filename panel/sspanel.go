package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type SSPanel struct {
	URL string
	Key string
}

type SSPanelUser struct {
	ID          int    `json:"id"`
	UUID        string `json:"uuid"`
	AliveIP     int    `json:"alive_ip"`
	NodeIPLimit int    `json:"node_iplimit"`
}

type SSPanelUsersResponse struct {
	Ret  int           `json:"ret"`
	Data []SSPanelUser `json:"data"`
}

type SSPanelOnlineIPRequest struct {
	UserID int    `json:"user_id"`
	IP     string `json:"ip"`
}

type SSPanelOnlineIPResponse struct {
	Ret  int    `json:"ret"`
	Data string `json:"data"`
}

type SSPanelHeartbeatResponse struct {
	Ret  int `json:"ret"`
	Data struct {
		Server       string `json:"server"`
		CustomConfig struct {
			Path string `json:"path"`
		} `json:"custom_config"`
	} `json:"data"`
}

func NewSSPanel(url, key string) *SSPanel {
	return &SSPanel{
		URL: url,
		Key: key,
	}
}

func (p *SSPanel) Heartbeat(nodeID int) (string, error) {
	url := fmt.Sprintf("%s/mod_mu/nodes/%d/info?key=%s&muKey=%s", p.URL, nodeID, p.Key, p.Key)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	if unmarshalErr := json.Unmarshal(body, &result); unmarshalErr != nil {
		return "", unmarshalErr
	}

	if ret, ok := result["ret"].(float64); ok && ret == 0 {
		return "", err
	}

	var heartbeatResp SSPanelHeartbeatResponse
	if unmarshalErr := json.Unmarshal(body, &heartbeatResp); unmarshalErr != nil {
		return "", unmarshalErr
	}

	nodeAddress := heartbeatResp.Data.Server + heartbeatResp.Data.CustomConfig.Path
	return nodeAddress, nil
}

func (p *SSPanel) GetUsers(nodeID int) ([]SSPanelUser, error) {
	url := fmt.Sprintf("%s/mod_mu/users?node_id=%d&key=%s&muKey=%s", p.URL, nodeID, p.Key, p.Key)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if unmarshalErr := json.Unmarshal(body, &result); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	if ret, ok := result["ret"].(float64); ok && ret == 0 {
		return nil, err
	}

	var usersResponse SSPanelUsersResponse
	if unmarshalErr := json.Unmarshal(body, &usersResponse); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return usersResponse.Data, nil
}

func (p *SSPanel) ReportOnlineIPs(nodeID int, ips []SSPanelOnlineIPRequest) error {
	url := fmt.Sprintf("%s/mod_mu/users/aliveip?node_id=%d&key=%s&muKey=%s", p.URL, nodeID, p.Key, p.Key)

	requestBody := map[string][]SSPanelOnlineIPRequest{
		"data": ips,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result SSPanelOnlineIPResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	return nil
}
