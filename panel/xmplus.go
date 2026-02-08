package panel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type XMPlusPanel struct {
	URL string
	Key string
}

type XMPlusSubscription struct {
	ID      int    `json:"id"`
	UUID    string `json:"uuid"`
	IPCount int    `json:"ipcount"`
	IPLimit int    `json:"iplimit"`
}

type XMPlusSubscriptionsResponse struct {
	Subscriptions []XMPlusSubscription `json:"subscriptions"`
}

type XMPlusOnlineIPRequest struct {
	SubscriptionID int    `json:"subscription_id"`
	IP             string `json:"ip"`
}

type XMPlusOnlineIPResponse struct {
	Data string `json:"data"`
}

type XMPlusHeartbeatResponse struct {
	Server struct {
		Address         string `json:"address"`
		NetworkSettings struct {
			Path string `json:"path"`
		} `json:"networkSettings"`
	} `json:"server"`
}

func NewXMPlusPanel(url, key string) *XMPlusPanel {
	return &XMPlusPanel{
		URL: url,
		Key: key,
	}
}

func (p *XMPlusPanel) Heartbeat(nodeID int) (string, error) {
	url := fmt.Sprintf("%s/api/server/%d?key=%s", p.URL, nodeID, p.Key)

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

	var heartbeatResp XMPlusHeartbeatResponse
	if unmarshalErr := json.Unmarshal(body, &heartbeatResp); unmarshalErr != nil {
		return "", unmarshalErr
	}

	nodeAddress := heartbeatResp.Server.Address + heartbeatResp.Server.NetworkSettings.Path
	return nodeAddress, nil
}

func (p *XMPlusPanel) GetSubscriptions(nodeID int) ([]XMPlusSubscription, error) {
	url := fmt.Sprintf("%s/api/subscriptions/%d?key=%s", p.URL, nodeID, p.Key)

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

	var subscriptionsResponse XMPlusSubscriptionsResponse
	if unmarshalErr := json.Unmarshal(body, &subscriptionsResponse); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return subscriptionsResponse.Subscriptions, nil
}

func (p *XMPlusPanel) ReportOnlineIPs(nodeID int, ips []XMPlusOnlineIPRequest) error {
	url := fmt.Sprintf("%s/api/onlineip/%d?key=%s", p.URL, nodeID, p.Key)

	requestBody := map[string][]XMPlusOnlineIPRequest{
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

	var result XMPlusOnlineIPResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}

	return nil
}
