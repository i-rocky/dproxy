package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"dproxy/internal/fault"
	"github.com/pelletier/go-toml/v2"
)

var (
	ErrTrustRequired = errors.New("explicit repository trust required")
	ErrNotFound      = errors.New("plugin not found")
	ErrAmbiguous     = errors.New("ambiguous plugin provider")
)

type TrustDecision struct{ Explicit bool }

type Repository struct {
	Name           string            `toml:"name"`
	URL            string            `toml:"url"`
	Commit         string            `toml:"commit"`
	ManifestHashes map[string]string `toml:"manifest_hashes"`
}

type storeIndex struct {
	Schema       int          `toml:"schema"`
	Repositories []Repository `toml:"repositories"`
}

type Store struct {
	root  string
	git   Git
	index storeIndex
}

func NewStore(root string, git Git) (*Store, error) {
	if git == nil {
		git = execGit{}
	}
	if err := os.MkdirAll(filepath.Join(root, "repos"), 0o700); err != nil {
		return nil, fault.New("open plugin store", "create failed", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fault.New("open plugin store", "permissions failed", err)
	}
	s := &Store{root: root, git: git, index: storeIndex{Schema: 1}}
	raw, err := os.ReadFile(filepath.Join(root, "index.toml"))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fault.New("open plugin store", "index read failed", err)
	}
	decoder := toml.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s.index); err != nil || s.index.Schema != 1 {
		return nil, fault.New("open plugin store", "invalid index", err)
	}
	for _, repository := range s.index.Repositories {
		if validateStoredRepository(repository) != nil {
			return nil, fault.New("open plugin store", "invalid index", nil)
		}
	}
	return s, nil
}

func (s *Store) Add(ctx context.Context, repositoryURL string, trust TrustDecision) (Repository, error) {
	if !trust.Explicit {
		return Repository{}, fault.New("add plugin repository", "trust required", ErrTrustRequired)
	}
	if err := validateRepositoryURL(repositoryURL); err != nil {
		return Repository{}, err
	}
	name := repositoryName(repositoryURL)
	for _, repository := range s.index.Repositories {
		if repository.Name == name || repository.URL == repositoryURL {
			return Repository{}, fault.New("add plugin repository", "already exists", nil)
		}
	}
	directory := filepath.Join(s.root, "repos", name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return Repository{}, fault.New("add plugin repository", "create checkout failed", err)
	}
	if _, err := s.run(ctx, directory, "init"); err != nil {
		return Repository{}, fault.New("add plugin repository", "Git initialization failed", err)
	}
	if _, err := s.run(ctx, directory, "remote", "add", "origin", repositoryURL); err != nil {
		return Repository{}, fault.New("add plugin repository", "Git remote failed", err)
	}
	repository, err := s.synchronize(ctx, Repository{Name: name, URL: repositoryURL})
	if err != nil {
		return Repository{}, err
	}
	s.index.Repositories = append(s.index.Repositories, repository)
	if err := s.persist(); err != nil {
		return Repository{}, err
	}
	return repository, nil
}

func (s *Store) Sync(ctx context.Context, repositoryName string) (Repository, error) {
	for i, repository := range s.index.Repositories {
		if repository.Name != repositoryName {
			continue
		}
		updated, err := s.synchronize(ctx, repository)
		if err != nil {
			return Repository{}, err
		}
		s.index.Repositories[i] = updated
		if err := s.persist(); err != nil {
			return Repository{}, err
		}
		return updated, nil
	}
	return Repository{}, fault.New("sync plugin repository", "repository not found", ErrNotFound)
}

func (s *Store) Resolve(binary string) (Manifest, error) {
	var result Manifest
	found := false
	for _, repository := range s.index.Repositories {
		for manifestPath, expected := range repository.ManifestHashes {
			raw, err := readRegular(filepath.Join(s.root, "repos", repository.Name, filepath.FromSlash(manifestPath)))
			if err != nil || hash(raw) != expected {
				return Manifest{}, fault.New("resolve plugin", "stored manifest verification failed", err)
			}
			manifest, err := LoadManifest(bytes.NewReader(raw))
			if err != nil {
				return Manifest{}, err
			}
			for _, provided := range manifest.Bins {
				if provided == binary {
					if found {
						return Manifest{}, fault.New("resolve plugin", "ambiguous provider", ErrAmbiguous)
					}
					result, found = manifest, true
				}
			}
		}
	}
	if !found {
		return Manifest{}, fault.New("resolve plugin", "binary not found", ErrNotFound)
	}
	return result, nil
}

func (s *Store) synchronize(ctx context.Context, repository Repository) (Repository, error) {
	directory := filepath.Join(s.root, "repos", repository.Name)
	if _, err := s.run(ctx, directory, "fetch", "--depth=1", "origin", "HEAD"); err != nil {
		return Repository{}, fault.New("sync plugin repository", "Git fetch failed", err)
	}
	commitRaw, err := s.run(ctx, directory, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return Repository{}, fault.New("sync plugin repository", "commit resolution failed", err)
	}
	commit := strings.TrimSpace(string(commitRaw))
	if !isHexCommit(commit) {
		return Repository{}, fault.New("sync plugin repository", "invalid commit", nil)
	}
	if _, err := s.run(ctx, directory, "checkout", "--detach", "--force", commit); err != nil {
		return Repository{}, fault.New("sync plugin repository", "detached checkout failed", err)
	}
	tree, err := s.run(ctx, directory, "ls-tree", "-rz", "--full-tree", commit)
	if err != nil {
		return Repository{}, fault.New("sync plugin repository", "tree inspection failed", err)
	}
	paths, err := validateTree(tree)
	if err != nil {
		return Repository{}, err
	}
	hashes := make(map[string]string, len(paths))
	providers := make(map[string]struct{})
	for _, manifestPath := range paths {
		raw, err := readRegular(filepath.Join(directory, filepath.FromSlash(manifestPath)))
		if err != nil {
			return Repository{}, fault.New("sync plugin repository", "manifest read failed", err)
		}
		manifest, err := LoadManifest(bytes.NewReader(raw))
		if err != nil {
			return Repository{}, err
		}
		for _, binary := range manifest.Bins {
			if _, exists := providers[binary]; exists {
				return Repository{}, fault.New("sync plugin repository", "duplicate binary provider", ErrAmbiguous)
			}
			providers[binary] = struct{}{}
		}
		hashes[manifestPath] = hash(raw)
	}
	if len(hashes) == 0 {
		return Repository{}, fault.New("sync plugin repository", "no manifests", nil)
	}
	repository.Commit, repository.ManifestHashes = commit, hashes
	return repository, nil
}

func (s *Store) run(ctx context.Context, directory string, args ...string) ([]byte, error) {
	hooks := filepath.Join(s.root, "hooks-empty")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		return nil, err
	}
	literal := append([]string{"-c", "core.hooksPath=" + hooks}, args...)
	return s.git.Run(ctx, directory, literal)
}

func validateTree(raw []byte) ([]string, error) {
	var paths []string
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		metadata := strings.Fields(string(parts[0]))
		if len(parts) != 2 || len(metadata) != 3 || metadata[0] != "100644" || metadata[1] != "blob" {
			return nil, fault.New("sync plugin repository", "unsafe indexed tree", nil)
		}
		name := string(parts[1])
		if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, ".") || filepath.Ext(name) != ".toml" {
			return nil, fault.New("sync plugin repository", "non-manifest indexed file", nil)
		}
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths, nil
}

func (s *Store) persist() error {
	raw, err := toml.Marshal(s.index)
	if err != nil {
		return fault.New("persist plugin store", "encode failed", err)
	}
	temporary, err := os.CreateTemp(s.root, ".index-*")
	if err != nil {
		return fault.New("persist plugin store", "temporary file failed", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fault.New("persist plugin store", "permissions failed", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fault.New("persist plugin store", "write failed", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fault.New("persist plugin store", "sync failed", err)
	}
	if err := temporary.Close(); err != nil {
		return fault.New("persist plugin store", "close failed", err)
	}
	if err := os.Rename(temporaryName, filepath.Join(s.root, "index.toml")); err != nil {
		return fault.New("persist plugin store", "publish failed", err)
	}
	return nil
}

func validateRepositoryURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "ssh") || parsed.Host == "" || parsed.User != nil {
		return fault.New("add plugin repository", "invalid URL", nil)
	}
	return nil
}

func validateStoredRepository(repository Repository) error {
	if validateRepositoryURL(repository.URL) != nil || repository.Name != repositoryName(repository.URL) || !isHexCommit(repository.Commit) || len(repository.ManifestHashes) == 0 {
		return errors.New("invalid repository")
	}
	for name, digest := range repository.ManifestHashes {
		if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, ".") || filepath.Ext(name) != ".toml" || len(digest) != sha256.Size*2 {
			return errors.New("invalid manifest record")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("invalid manifest hash")
		}
	}
	return nil
}

func repositoryName(value string) string { return hash([]byte(value))[:32] }
func hash(value []byte) string           { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }

func isHexCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readRegular(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return os.ReadFile(name)
}
