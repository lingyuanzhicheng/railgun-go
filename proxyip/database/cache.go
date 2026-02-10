package database

import (
	"fmt"
	"sync"
)

type CacheDB struct {
	proxyIPs map[string]*proxyIPRecord
	dbMutex  sync.RWMutex
}

type proxyIPRecord struct {
	ip     string
	port   string
	code   string
	org    string
	status string
}

func NewCacheDB() *CacheDB {
	return &CacheDB{
		proxyIPs: make(map[string]*proxyIPRecord),
	}
}

func (c *CacheDB) Init() error {
	fmt.Println("使用proxyip内存缓存模式")
	return nil
}

func (c *CacheDB) GetAll() ([]ProxyIP, error) {
	c.dbMutex.RLock()
	defer c.dbMutex.RUnlock()

	var result []ProxyIP
	for _, record := range c.proxyIPs {
		result = append(result, ProxyIP{
			IP:     record.ip,
			Port:   record.port,
			Code:   record.code,
			Org:    record.org,
			Status: record.status,
		})
	}
	return result, nil
}

func (c *CacheDB) GetValid() ([]ProxyIP, error) {
	c.dbMutex.RLock()
	defer c.dbMutex.RUnlock()

	var result []ProxyIP
	for _, record := range c.proxyIPs {
		if record.status == "valid" {
			result = append(result, ProxyIP{
				IP:     record.ip,
				Port:   record.port,
				Code:   record.code,
				Org:    record.org,
				Status: record.status,
			})
		}
	}
	return result, nil
}

func (c *CacheDB) GetByCode(code string) ([]ProxyIP, error) {
	c.dbMutex.RLock()
	defer c.dbMutex.RUnlock()

	var result []ProxyIP
	for _, record := range c.proxyIPs {
		if record.code == code {
			result = append(result, ProxyIP{
				IP:     record.ip,
				Port:   record.port,
				Code:   record.code,
				Org:    record.org,
				Status: record.status,
			})
		}
	}
	return result, nil
}

func (c *CacheDB) UpdateStatus(ip, port, status string) error {
	c.dbMutex.Lock()
	defer c.dbMutex.Unlock()

	key := fmt.Sprintf("%s:%s", ip, port)
	if record, exists := c.proxyIPs[key]; exists {
		record.status = status
	}
	return nil
}

func (c *CacheDB) Insert(ip, port, code, org, status string) error {
	c.dbMutex.Lock()
	defer c.dbMutex.Unlock()

	key := fmt.Sprintf("%s:%s", ip, port)
	c.proxyIPs[key] = &proxyIPRecord{
		ip:     ip,
		port:   port,
		code:   code,
		org:    org,
		status: status,
	}
	return nil
}

func (c *CacheDB) UpdateAllStatus(status string) error {
	c.dbMutex.Lock()
	defer c.dbMutex.Unlock()

	for _, record := range c.proxyIPs {
		record.status = status
	}
	return nil
}

func (c *CacheDB) Close() error {
	return nil
}
