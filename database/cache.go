package database

import (
	"fmt"
	"sync"
)

type CacheDB struct {
	aliveIPs map[string]*aliveIPRecord
	uuids    map[string]*uuidRecord
	dbMutex  sync.RWMutex
}

type aliveIPRecord struct {
	railgunid int
	uid       int
	ip        string
}

type uuidRecord struct {
	railgunid int
	uid       int
	uuid      string
	ipquota   int
}

func NewCacheDB() *CacheDB {
	return &CacheDB{
		aliveIPs: make(map[string]*aliveIPRecord),
		uuids:    make(map[string]*uuidRecord),
	}
}

func (c *CacheDB) Init() error {
	fmt.Println("内存数据库初始化成功")
	return nil
}

func (c *CacheDB) ClearAliveIPs(railgunID int) error {
	c.dbMutex.Lock()
	defer c.dbMutex.Unlock()

	for key := range c.aliveIPs {
		if c.aliveIPs[key].railgunid == railgunID {
			delete(c.aliveIPs, key)
		}
	}
	return nil
}

func (c *CacheDB) InsertAliveIP(railgunID, uid int, ip string) error {
	c.dbMutex.Lock()
	defer c.dbMutex.Unlock()

	key := fmt.Sprintf("%d-%d-%s", railgunID, uid, ip)
	c.aliveIPs[key] = &aliveIPRecord{
		railgunid: railgunID,
		uid:       uid,
		ip:        ip,
	}
	return nil
}

func (c *CacheDB) GetAliveIPs(railgunID int) ([]AliveIP, error) {
	c.dbMutex.RLock()
	defer c.dbMutex.RUnlock()

	var result []AliveIP
	for _, record := range c.aliveIPs {
		if record.railgunid == railgunID {
			result = append(result, AliveIP{
				RailgunID: record.railgunid,
				UID:       record.uid,
				IP:        record.ip,
			})
		}
	}
	return result, nil
}

func (c *CacheDB) ClearUUIDs(railgunID int) error {
	c.dbMutex.Lock()
	defer c.dbMutex.Unlock()

	for key := range c.uuids {
		if c.uuids[key].railgunid == railgunID {
			delete(c.uuids, key)
		}
	}
	return nil
}

func (c *CacheDB) InsertUUID(railgunID, uid int, uuid string, ipquota int) error {
	c.dbMutex.Lock()
	defer c.dbMutex.Unlock()

	key := fmt.Sprintf("%d-%d-%s", railgunID, uid, uuid)
	c.uuids[key] = &uuidRecord{
		railgunid: railgunID,
		uid:       uid,
		uuid:      uuid,
		ipquota:   ipquota,
	}
	return nil
}

func (c *CacheDB) GetUUID(railgunID int, uuid string) (*UUIDRecord, error) {
	c.dbMutex.RLock()
	defer c.dbMutex.RUnlock()

	for _, record := range c.uuids {
		if record.railgunid == railgunID && record.uuid == uuid {
			return &UUIDRecord{
				RailgunID: record.railgunid,
				UID:       record.uid,
				UUID:      record.uuid,
				IPQuota:   record.ipquota,
			}, nil
		}
	}
	return nil, nil
}

func (c *CacheDB) GetAliveIPCount(railgunID, uid int) (int, error) {
	c.dbMutex.RLock()
	defer c.dbMutex.RUnlock()

	count := 0
	for _, record := range c.aliveIPs {
		if record.railgunid == railgunID && record.uid == uid {
			count++
		}
	}
	return count, nil
}

func (c *CacheDB) Close() error {
	return nil
}
