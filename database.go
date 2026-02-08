package main

import (
	"railgun-go/database"
)

type AliveIP struct {
	RailgunID int
	UID       int
	IP        string
}

type UUIDRecord struct {
	RailgunID int
	UID       int
	UUID      string
	IPQuota   int
}

type Database interface {
	Init() error
	ClearAliveIPs(railgunID int) error
	InsertAliveIP(railgunID, uid int, ip string) error
	GetAliveIPs(railgunID int) ([]database.AliveIP, error)
	ClearUUIDs(railgunID int) error
	InsertUUID(railgunID, uid int, uuid string, ipquota int) error
	GetUUID(railgunID int, uuid string) (*database.UUIDRecord, error)
	GetAliveIPCount(railgunID, uid int) (int, error)
	Close() error
}

var db Database

func InitDB() error {
	switch GlobalConfig.Data {
	case "cache":
		db = database.NewCacheDB()
	case "sqlite":
		db = database.NewSQLiteDB()
	default:
		db = database.NewSQLiteDB()
	}
	return db.Init()
}

func ClearAliveIPs(railgunID int) error {
	return db.ClearAliveIPs(railgunID)
}

func InsertAliveIP(railgunID, uid int, ip string) error {
	return db.InsertAliveIP(railgunID, uid, ip)
}

func GetAliveIPs(railgunID int) ([]AliveIP, error) {
	dbAliveIPs, err := db.GetAliveIPs(railgunID)
	if err != nil {
		return nil, err
	}

	var result []AliveIP
	for _, dbAliveIP := range dbAliveIPs {
		result = append(result, AliveIP{
			RailgunID: dbAliveIP.RailgunID,
			UID:       dbAliveIP.UID,
			IP:        dbAliveIP.IP,
		})
	}
	return result, nil
}

func ClearUUIDs(railgunID int) error {
	return db.ClearUUIDs(railgunID)
}

func InsertUUID(railgunID, uid int, uuid string, ipquota int) error {
	return db.InsertUUID(railgunID, uid, uuid, ipquota)
}

func GetUUID(railgunID int, uuid string) (*UUIDRecord, error) {
	dbUUIDRecord, err := db.GetUUID(railgunID, uuid)
	if err != nil {
		return nil, err
	}

	if dbUUIDRecord == nil {
		return nil, nil
	}

	return &UUIDRecord{
		RailgunID: dbUUIDRecord.RailgunID,
		UID:       dbUUIDRecord.UID,
		UUID:      dbUUIDRecord.UUID,
		IPQuota:   dbUUIDRecord.IPQuota,
	}, nil
}

func GetAliveIPCount(railgunID, uid int) (int, error) {
	return db.GetAliveIPCount(railgunID, uid)
}

func CloseDB() error {
	return db.Close()
}
