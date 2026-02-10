package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

type ProxyIP struct {
	IP     string
	Port   string
	Code   string
	Org    string
	Status string
}

type SQLiteDB struct {
	db      *sql.DB
	dbMutex sync.Mutex
}

func NewSQLiteDB() *SQLiteDB {
	return &SQLiteDB{}
}

func (s *SQLiteDB) Init() error {
	dbPath := filepath.Join("config", "proxyip.db")

	_, err := os.Stat(dbPath)
	dbExists := !os.IsNotExist(err)

	var errOpen error
	s.db, errOpen = sql.Open("sqlite3", dbPath)
	if errOpen != nil {
		return fmt.Errorf("打开数据库失败: %v", errOpen)
	}

	if err := s.db.Ping(); err != nil {
		return fmt.Errorf("连接数据库失败: %v", err)
	}

	if !dbExists {
		if err := s.createTables(); err != nil {
			return fmt.Errorf("创建数据库表失败: %v", err)
		}
		fmt.Println("proxyip数据库文件创建成功")
	} else {
		fmt.Println("proxyip数据库文件已存在")
	}

	return nil
}

func (s *SQLiteDB) createTables() error {
	createProxyIPTable := `
	CREATE TABLE IF NOT EXISTS proxyip (
		ip TEXT PRIMARY KEY,
		port TEXT,
		code TEXT,
		org TEXT,
		status TEXT
	);
	`

	if _, err := s.db.Exec(createProxyIPTable); err != nil {
		return fmt.Errorf("创建proxyip表失败: %v", err)
	}

	return nil
}

func (s *SQLiteDB) GetAll() ([]ProxyIP, error) {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	rows, err := s.db.Query("SELECT ip, port, code, org, status FROM proxyip")
	if err != nil {
		return nil, fmt.Errorf("查询proxyip记录失败: %v", err)
	}
	defer rows.Close()

	var proxyIPs []ProxyIP
	for rows.Next() {
		var proxyIP ProxyIP
		if err := rows.Scan(&proxyIP.IP, &proxyIP.Port, &proxyIP.Code, &proxyIP.Org, &proxyIP.Status); err != nil {
			return nil, fmt.Errorf("扫描proxyip记录失败: %v", err)
		}
		proxyIPs = append(proxyIPs, proxyIP)
	}

	return proxyIPs, nil
}

func (s *SQLiteDB) GetValid() ([]ProxyIP, error) {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	rows, err := s.db.Query("SELECT ip, port, code, org, status FROM proxyip WHERE status = 'valid'")
	if err != nil {
		return nil, fmt.Errorf("查询有效proxyip记录失败: %v", err)
	}
	defer rows.Close()

	var proxyIPs []ProxyIP
	for rows.Next() {
		var proxyIP ProxyIP
		if err := rows.Scan(&proxyIP.IP, &proxyIP.Port, &proxyIP.Code, &proxyIP.Org, &proxyIP.Status); err != nil {
			return nil, fmt.Errorf("扫描有效proxyip记录失败: %v", err)
		}
		proxyIPs = append(proxyIPs, proxyIP)
	}

	return proxyIPs, nil
}

func (s *SQLiteDB) GetByCode(code string) ([]ProxyIP, error) {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	rows, err := s.db.Query("SELECT ip, port, code, org, status FROM proxyip WHERE code = ?", code)
	if err != nil {
		return nil, fmt.Errorf("根据code查询proxyip记录失败: %v", err)
	}
	defer rows.Close()

	var proxyIPs []ProxyIP
	for rows.Next() {
		var proxyIP ProxyIP
		if err := rows.Scan(&proxyIP.IP, &proxyIP.Port, &proxyIP.Code, &proxyIP.Org, &proxyIP.Status); err != nil {
			return nil, fmt.Errorf("扫描proxyip记录失败: %v", err)
		}
		proxyIPs = append(proxyIPs, proxyIP)
	}

	return proxyIPs, nil
}

func (s *SQLiteDB) UpdateStatus(ip, port, status string) error {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	_, err := s.db.Exec("UPDATE proxyip SET status = ? WHERE ip = ? AND port = ?", status, ip, port)
	if err != nil {
		return fmt.Errorf("更新proxyip状态失败: %v", err)
	}
	return nil
}

func (s *SQLiteDB) UpdateAllStatus(status string) error {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	_, err := s.db.Exec("UPDATE proxyip SET status = ?", status)
	if err != nil {
		return fmt.Errorf("更新所有proxyip状态失败: %v", err)
	}
	return nil
}

func (s *SQLiteDB) Insert(ip, port, code, org, status string) error {
	s.dbMutex.Lock()
	defer s.dbMutex.Unlock()

	_, err := s.db.Exec("INSERT OR REPLACE INTO proxyip (ip, port, code, org, status) VALUES (?, ?, ?, ?, ?)", ip, port, code, org, status)
	if err != nil {
		return fmt.Errorf("插入proxyip记录失败: %v", err)
	}
	return nil
}

func (s *SQLiteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
