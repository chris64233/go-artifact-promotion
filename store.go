package artifactpromotion

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// state 是服务的全部持久化状态。
type state struct {
	Artifacts    map[string]Artifact         `json:"artifacts"`
	Attestations map[string]Attestation      `json:"attestations"`
	Policies     map[string]Policy           `json:"policies"`
	Environments map[string]EnvironmentState `json:"environments"`
	// Changes 以外部变更号为索引的晋级记录，用于幂等判定。
	Changes map[string]PromotionRecord `json:"changes"`
	// History 按发生顺序排列的全部晋级记录。
	History []PromotionRecord `json:"history"`
}

func newState() *state {
	return &state{
		Artifacts:    map[string]Artifact{},
		Attestations: map[string]Attestation{},
		Policies:     map[string]Policy{},
		Environments: map[string]EnvironmentState{},
		Changes:      map[string]PromotionRecord{},
	}
}

// Store 负责服务状态的加载与持久化。
type Store interface {
	Load() (*state, error)
	Save(s *state) error
}

// FileStore 把状态以 JSON 形式持久化到单个文件，
// 写入时先写临时文件再原子重命名，避免半截文件。
type FileStore struct {
	path string
}

// NewFileStore 创建一个以 path 为存储文件的 Store。
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

// Load 读取状态文件；文件不存在时返回空状态。
func (f *FileStore) Load() (*state, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state file: %w", err)
	}
	st := newState()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("decode state file: %w", err)
	}
	return st, nil
}

// Save 把状态原子写入存储文件。
func (f *FileStore) Save(s *state) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}

// MemStore 是不落盘的内存 Store，主要用于测试。
type MemStore struct {
	saved *state
}

// Load 返回最近一次保存的状态（浅拷贝顶层结构）。
func (m *MemStore) Load() (*state, error) {
	if m.saved == nil {
		return newState(), nil
	}
	return m.saved, nil
}

// Save 记录状态引用。
func (m *MemStore) Save(s *state) error {
	m.saved = s
	return nil
}
