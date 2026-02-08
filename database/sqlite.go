package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
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

type SQLiteDB struct {
	db      *sql.DB
	dbMutex sync.Mutex
}

func NewSQLiteDB() *SQLiteDB {
	return &SQLiteDB{}
}

func (s *SQLiteDB) Init() error {
	dbPath := filepath.Join("config", "railgun.db")

	err := os.Remove(dbPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("重置数据库文件失败: %v", err)
	}

	var errOpen error
	s.db, errOpen = sql.Open("sqlite3", dbPath)
	if errOpen != nil {
		return fmt.Errorf("打开数据库失败: %v", errOpen)
	}

	if err := s.db.Ping(); err != nil {
		return fmt.Errorf("连接数据库失败: %v", err)
	}

	if err := s.createTables(); err != nil {
		return fmt.Errorf("创建数据库表失败: %v", err)
	}
	fmt.Println("数据库文件初始化成功")

	return nil
}

func (s *SQLiteDB) createTables() error {
	createAliveIPTable := `
	CREATE TABLE IF NOT EXISTS aliveip (
		railgunid INTEGER NOT NULL,
		uid INTEGER NOT NULL,
		ip TEXT NOT NULL,
		PRIMARY KEY (railgunid, uid, ip)
	);
	`

	createUUIDsTable := `
	CREATE TABLE IF NOT EXISTS uuids (
		railgunid INTEGER NOT NULL,
		uid INTEGER NOT NULL,
		uuid TEXT NOT NULL,
		ipquota INTEGER NOT NULL,
		PRIMARY KEY (railgunid, uid, uuid)
	);
	`

	if _, err := s.db.Exec(createAliveIPTable); err != nil {
		return fmt.Errorf("创建aliveip表失败: %v", err)
	}

	if _, err := s.db.Exec(createUUIDsTable); err != nil {
		return fmt.Errorf("创建uuids表失败: %v", err)
	}

	return nil
}

func (s *SQLiteDB) ClearAliveIPs(railgunID int) error {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	_, err := s.db.Exec("DELETE FROM aliveip WHERE railgunid = ?", railgunID)
	if err != nil {
		return fmt.Errorf("清空aliveip表失败: %v", err)
	}
	return nil
}

func (s *SQLiteDB) InsertAliveIP(railgunID, uid int, ip string) error {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	_, err := s.db.Exec("INSERT OR REPLACE INTO aliveip (railgunid, uid, ip) VALUES (?, ?, ?)", railgunID, uid, ip)
	if err != nil {
		return fmt.Errorf("插入aliveip记录失败: %v", err)
	}
	return nil
}

func (s *SQLiteDB) GetAliveIPs(railgunID int) ([]AliveIP, error) {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	rows, err := s.db.Query("SELECT railgunid, uid, ip FROM aliveip WHERE railgunid = ?", railgunID)
	if err != nil {
		return nil, fmt.Errorf("查询aliveip记录失败: %v", err)
	}
	defer rows.Close()

	var aliveIPs []AliveIP
	for rows.Next() {
		var aliveIP AliveIP
		if err := rows.Scan(&aliveIP.RailgunID, &aliveIP.UID, &aliveIP.IP); err != nil {
			return nil, fmt.Errorf("扫描aliveip记录失败: %v", err)
		}
		aliveIPs = append(aliveIPs, aliveIP)
	}

	return aliveIPs, nil
}

func (s *SQLiteDB) ClearUUIDs(railgunID int) error {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	_, err := s.db.Exec("DELETE FROM uuids WHERE railgunid = ?", railgunID)
	if err != nil {
		return fmt.Errorf("清空uuids表失败: %v", err)
	}
	return nil
}

func (s *SQLiteDB) InsertUUID(railgunID, uid int, uuid string, ipquota int) error {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	_, err := s.db.Exec("INSERT OR REPLACE INTO uuids (railgunid, uid, uuid, ipquota) VALUES (?, ?, ?, ?)", railgunID, uid, uuid, ipquota)
	if err != nil {
		return fmt.Errorf("插入uuid记录失败: %v", err)
	}
	return nil
}

func (s *SQLiteDB) GetUUID(railgunID int, uuid string) (*UUIDRecord, error) {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	var record UUIDRecord
	err := s.db.QueryRow("SELECT railgunid, uid, uuid, ipquota FROM uuids WHERE railgunid = ? AND uuid = ?", railgunID, uuid).Scan(&record.RailgunID, &record.UID, &record.UUID, &record.IPQuota)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("查询uuid记录失败: %v", err)
	}
	return &record, nil
}

func (s *SQLiteDB) GetAliveIPCount(railgunID, uid int) (int, error) {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM aliveip WHERE railgunid = ? AND uid = ?", railgunID, uid).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("查询在线IP数量失败: %v", err)
	}
	return count, nil
}

func (s *SQLiteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
