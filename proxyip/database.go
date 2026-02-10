package proxyip

import "railgun-go/proxyip/database"

type ProxyIP = database.ProxyIP

type Database interface {
	Init() error
	GetAll() ([]ProxyIP, error)
	GetValid() ([]ProxyIP, error)
	GetByCode(code string) ([]ProxyIP, error)
	UpdateStatus(ip, port, status string) error
	UpdateAllStatus(status string) error
	Insert(ip, port, code, org, status string) error
	Close() error
}

var db Database

func InitDB(dataType string) error {
	switch dataType {
	case "cache":
		db = database.NewCacheDB()
	case "sqlite":
		db = database.NewSQLiteDB()
	default:
		db = database.NewSQLiteDB()
	}
	return db.Init()
}

func GetAll() ([]ProxyIP, error) {
	return db.GetAll()
}

func GetValid() ([]ProxyIP, error) {
	return db.GetValid()
}

func GetByCode(code string) ([]ProxyIP, error) {
	return db.GetByCode(code)
}

func UpdateStatus(ip, port, status string) error {
	return db.UpdateStatus(ip, port, status)
}

func UpdateAllStatus(status string) error {
	return db.UpdateAllStatus(status)
}

func Insert(ip, port, code, org, status string) error {
	return db.Insert(ip, port, code, org, status)
}

func CloseDB() error {
	return db.Close()
}
