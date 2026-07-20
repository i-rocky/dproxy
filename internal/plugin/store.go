package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/i-rocky/dproxy/internal/fault"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
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
	root                 string
	git                  Git
	index                storeIndex
	renameIndex          func(string, string) error
	syncRoot             func() error
	syncReposRoot        func() error
	syncGenerationParent func(string) error
}

func NewStore(root string, git Git) (*Store, error) {
	return openStore(root, git, true)
}

// OpenStore opens existing plugin metadata without creating filesystem state.
func OpenStore(root string, git Git) (*Store, error) {
	return openStore(root, git, false)
}

func openStore(root string, git Git, create bool) (*Store, error) {
	if git == nil {
		git = execGit{}
	}
	home := filepath.Join(root, "git-home")
	if !create {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return nil, ErrNotFound
		}
	} else {
		if err := os.MkdirAll(filepath.Join(root, "repos"), 0o700); err != nil {
			return nil, fault.New("open plugin store", "create failed", err)
		}
		if err := syncDirectory(root); err != nil {
			return nil, fault.New("open plugin store", "root sync failed", err)
		}
		if err := syncDirectory(filepath.Join(root, "repos")); err != nil {
			return nil, fault.New("open plugin store", "repositories sync failed", err)
		}
		if err := os.Chmod(root, 0o700); err != nil {
			return nil, fault.New("open plugin store", "permissions failed", err)
		}
		if err := os.MkdirAll(home, 0o700); err != nil {
			return nil, fault.New("open plugin store", "Git home failed", err)
		}
	}
	s := &Store{root: root, git: git, index: storeIndex{Schema: 1}}
	s.renameIndex = os.Rename
	s.syncRoot = func() error { return syncDirectory(root) }
	s.syncReposRoot = func() error { return syncDirectory(filepath.Join(root, "repos")) }
	s.syncGenerationParent = syncDirectory
	if _, ok := git.(execGit); ok {
		s.git = execGit{executable: "/usr/bin/git", home: home}
	}
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
	normalizedURL, err := normalizeRepositoryURL(repositoryURL)
	if err != nil {
		return Repository{}, err
	}
	repositoryURL = normalizedURL
	name := repositoryName(repositoryURL)
	for _, repository := range s.index.Repositories {
		if repository.Name == name || repository.URL == repositoryURL {
			return Repository{}, fault.New("add plugin repository", "already exists", nil)
		}
	}
	stage, err := os.MkdirTemp(s.root, ".repo-stage-")
	if err != nil {
		return Repository{}, fault.New("add plugin repository", "create checkout failed", err)
	}
	defer os.RemoveAll(stage)
	if _, err := s.run(ctx, stage, "init"); err != nil {
		return Repository{}, fault.New("add plugin repository", "Git initialization failed", err)
	}
	if _, err := s.run(ctx, stage, "remote", "add", "origin", repositoryURL); err != nil {
		return Repository{}, fault.New("add plugin repository", "Git remote failed", err)
	}
	repository, err := s.synchronize(ctx, stage, Repository{Name: name, URL: repositoryURL})
	if err != nil {
		return Repository{}, err
	}
	if err := s.ensureNoAmbiguity(repository, stage, ""); err != nil {
		return Repository{}, err
	}
	if err := s.publishGeneration(stage, repository); err != nil {
		return Repository{}, err
	}
	candidate := cloneIndex(s.index)
	candidate.Repositories = append(candidate.Repositories, repository)
	if err := s.persist(candidate); err != nil {
		return Repository{}, err
	}
	s.index = candidate
	return repository, nil
}

func (s *Store) Sync(ctx context.Context, repositoryName string) (Repository, error) {
	for i, repository := range s.index.Repositories {
		if repository.Name != repositoryName {
			continue
		}
		stage, err := os.MkdirTemp(s.root, ".repo-stage-")
		if err != nil {
			return Repository{}, fault.New("sync plugin repository", "create checkout failed", err)
		}
		defer os.RemoveAll(stage)
		if _, err := s.run(ctx, stage, "init"); err != nil {
			return Repository{}, fault.New("sync plugin repository", "Git initialization failed", err)
		}
		if _, err := s.run(ctx, stage, "remote", "add", "origin", repository.URL); err != nil {
			return Repository{}, fault.New("sync plugin repository", "Git remote failed", err)
		}
		updated, err := s.synchronize(ctx, stage, repository)
		if err != nil {
			return Repository{}, err
		}
		if err := s.ensureNoAmbiguity(updated, stage, repository.Name); err != nil {
			return Repository{}, err
		}
		if err := s.publishGeneration(stage, updated); err != nil {
			return Repository{}, err
		}
		candidate := cloneIndex(s.index)
		candidate.Repositories[i] = updated
		if err := s.persist(candidate); err != nil {
			return Repository{}, err
		}
		s.index = candidate
		return updated, nil
	}
	return Repository{}, fault.New("sync plugin repository", "repository not found", ErrNotFound)
}

func (s *Store) List() []Repository {
	result := make([]Repository, len(s.index.Repositories))
	for i, repository := range s.index.Repositories {
		result[i] = cloneRepository(repository)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (s *Store) Inspect(name string) (Repository, error) {
	for _, repository := range s.index.Repositories {
		if repository.Name == name {
			return cloneRepository(repository), nil
		}
	}
	return Repository{}, fault.New("inspect plugin repository", "repository not found", ErrNotFound)
}

func (s *Store) Remove(name string) error {
	index := -1
	var removed Repository
	for i, repository := range s.index.Repositories {
		if repository.Name == name {
			index, removed = i, repository
			break
		}
	}
	if index < 0 {
		return fault.New("remove plugin repository", "repository not found", ErrNotFound)
	}
	candidate := cloneIndex(s.index)
	candidate.Repositories = append(candidate.Repositories[:index], candidate.Repositories[index+1:]...)
	if err := s.persist(candidate); err != nil {
		return err
	}
	s.index = candidate
	directory := generationDirectory(s.root, removed)
	if info, err := os.Lstat(directory); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fault.New("remove plugin repository", "unsafe stored generation", nil)
		}
		if err := os.RemoveAll(directory); err != nil {
			return fault.New("remove plugin repository", "generation cleanup failed", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fault.New("remove plugin repository", "generation inspection failed", err)
	}
	return nil
}

func (s *Store) Resolve(binary string) (Manifest, error) {
	var result Manifest
	found := false
	for _, repository := range s.index.Repositories {
		for manifestPath, expected := range repository.ManifestHashes {
			raw, err := readRegularAt(generationDirectory(s.root, repository), manifestPath)
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
					manifest.Provenance = Provenance{Repository: repository.URL, Commit: repository.Commit, ManifestSHA256: expected, Schema: manifest.Schema}
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

func (s *Store) synchronize(ctx context.Context, directory string, repository Repository) (Repository, error) {
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
	tree, err := s.run(ctx, directory, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return Repository{}, fault.New("sync plugin repository", "tree inspection failed", err)
	}
	paths, err := validateTree(tree)
	if err != nil {
		return Repository{}, err
	}
	hashes := make(map[string]string, len(paths))
	providers := make(map[string]struct{})
	names := make(map[string]struct{})
	for _, manifestPath := range paths {
		raw, err := readRegularAt(directory, manifestPath)
		if err != nil {
			return Repository{}, fault.New("sync plugin repository", "manifest read failed", err)
		}
		manifest, err := LoadManifest(bytes.NewReader(raw))
		if err != nil {
			return Repository{}, err
		}
		if _, exists := names[manifest.Name]; exists {
			return Repository{}, fault.New("sync plugin repository", "duplicate plugin name", ErrAmbiguous)
		}
		names[manifest.Name] = struct{}{}
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

func (s *Store) publishGeneration(stage string, repository Repository) error {
	if err := fsyncTree(stage); err != nil {
		return fault.New("publish plugin generation", "staging sync failed", err)
	}
	parent := filepath.Join(s.root, "repos", repository.Name)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fault.New("publish plugin generation", "parent creation failed", err)
	}
	if err := s.syncReposRoot(); err != nil {
		return fault.New("publish plugin generation", "repositories root sync failed", err)
	}
	final := generationDirectory(s.root, repository)
	if _, err := os.Lstat(final); err == nil {
		if _, verifyErr := repositoryBinaries(final, repository.ManifestHashes); verifyErr != nil {
			return verifyErr
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fault.New("publish plugin generation", "generation inspection failed", err)
	} else if err := os.Rename(stage, final); err != nil {
		return fault.New("publish plugin generation", "generation rename failed", err)
	}
	if err := s.syncGenerationParent(parent); err != nil {
		return fault.New("publish plugin generation", "parent sync failed", err)
	}
	return nil
}

func fsyncTree(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, name)
			return nil
		}
		if entry.Type().IsRegular() {
			file, err := os.Open(name)
			if err != nil {
				return err
			}
			err = file.Sync()
			closeErr := file.Close()
			if err != nil {
				return err
			}
			return closeErr
		}
		return errors.New("unsafe staged entry")
	})
	if err != nil {
		return err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := syncDirectory(directories[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureNoAmbiguity(candidate Repository, candidateDirectory, replacing string) error {
	seen, err := repositoryBinaries(candidateDirectory, candidate.ManifestHashes)
	if err != nil {
		return err
	}
	for _, repository := range s.index.Repositories {
		if repository.Name == replacing {
			continue
		}
		binaries, err := repositoryBinaries(generationDirectory(s.root, repository), repository.ManifestHashes)
		if err != nil {
			return err
		}
		for binary := range binaries.bins {
			if _, exists := seen.bins[binary]; exists {
				return fault.New("sync plugin repository", "ambiguous provider", ErrAmbiguous)
			}
		}
		for name := range binaries.names {
			if _, exists := seen.names[name]; exists {
				return fault.New("sync plugin repository", "duplicate plugin name", ErrAmbiguous)
			}
		}
	}
	return nil
}

type repositorySymbols struct {
	bins  map[string]struct{}
	names map[string]struct{}
}

func repositoryBinaries(directory string, hashes map[string]string) (repositorySymbols, error) {
	symbols := repositorySymbols{bins: make(map[string]struct{}), names: make(map[string]struct{})}
	for manifestPath, expected := range hashes {
		raw, err := readRegularAt(directory, manifestPath)
		if err != nil || hash(raw) != expected {
			return repositorySymbols{}, fault.New("validate plugin repository", "manifest verification failed", err)
		}
		manifest, err := LoadManifest(bytes.NewReader(raw))
		if err != nil {
			return repositorySymbols{}, err
		}
		symbols.names[manifest.Name] = struct{}{}
		for _, binary := range manifest.Bins {
			symbols.bins[binary] = struct{}{}
		}
	}
	return symbols, nil
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
		if !validManifestPath(name) {
			return nil, fault.New("sync plugin repository", "non-manifest indexed file", nil)
		}
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths, nil
}

func (s *Store) persist(candidate storeIndex) error {
	indexPath := filepath.Join(s.root, "index.toml")
	previous, readErr := os.ReadFile(indexPath)
	hadPrevious := readErr == nil
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return fault.New("persist plugin store", "existing index read failed", readErr)
	}
	raw, err := toml.Marshal(candidate)
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
	if err := s.renameIndex(temporaryName, indexPath); err != nil {
		return fault.New("persist plugin store", "publish failed", err)
	}
	if err := s.syncRoot(); err != nil {
		s.restoreIndex(indexPath, previous, hadPrevious)
		return fault.New("persist plugin store", "directory sync failed", err)
	}
	return nil
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *Store) restoreIndex(indexPath string, previous []byte, existed bool) {
	if !existed {
		_ = os.Remove(indexPath)
		if directory, err := os.Open(s.root); err == nil {
			_ = directory.Sync()
			_ = directory.Close()
		}
		return
	}
	temporary, err := os.CreateTemp(s.root, ".index-restore-*")
	if err != nil {
		return
	}
	name := temporary.Name()
	defer os.Remove(name)
	_ = temporary.Chmod(0o600)
	_, writeErr := temporary.Write(previous)
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if writeErr == nil && syncErr == nil && closeErr == nil && os.Rename(name, indexPath) == nil {
		if directory, openErr := os.Open(s.root); openErr == nil {
			_ = directory.Sync()
			_ = directory.Close()
		}
	}
}

func normalizeRepositoryURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" || parsed.Path == "/" || strings.ContainsRune(parsed.Path, '\\') || strings.IndexFunc(parsed.Path, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || filepath.Clean(parsed.Path) != parsed.Path {
		return "", fault.New("add plugin repository", "invalid URL", nil)
	}
	hostname := strings.ToLower(parsed.Hostname())
	if !hostPattern.MatchString(hostname) {
		return "", fault.New("add plugin repository", "invalid URL", nil)
	}
	port := parsed.Port()
	if port != "" {
		n, parseErr := strconv.Atoi(port)
		if parseErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", fault.New("add plugin repository", "invalid URL", nil)
		}
	}
	if port == "443" {
		port = ""
	}
	parsed.Scheme = "https"
	parsed.Host = hostname
	if port != "" {
		parsed.Host += ":" + port
	}
	return parsed.String(), nil
}

var hostPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

func validateStoredRepository(repository Repository) error {
	normalized, err := normalizeRepositoryURL(repository.URL)
	if err != nil || normalized != repository.URL || repository.Name != repositoryName(repository.URL) || !isHexCommit(repository.Commit) || len(repository.ManifestHashes) == 0 {
		return errors.New("invalid repository")
	}
	for name, digest := range repository.ManifestHashes {
		if !validManifestPath(name) || len(digest) != sha256.Size*2 {
			return errors.New("invalid manifest record")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return errors.New("invalid manifest hash")
		}
	}
	return nil
}

func cloneIndex(index storeIndex) storeIndex {
	clone := storeIndex{Schema: index.Schema, Repositories: make([]Repository, len(index.Repositories))}
	for i, repository := range index.Repositories {
		clone.Repositories[i] = repository
		clone.Repositories[i].ManifestHashes = make(map[string]string, len(repository.ManifestHashes))
		for name, digest := range repository.ManifestHashes {
			clone.Repositories[i].ManifestHashes[name] = digest
		}
	}
	return clone
}

func cloneRepository(repository Repository) Repository {
	result := repository
	result.ManifestHashes = make(map[string]string, len(repository.ManifestHashes))
	for key, value := range repository.ManifestHashes {
		result.ManifestHashes[key] = value
	}
	return result
}

func generationDirectory(root string, repository Repository) string {
	return filepath.Join(root, "repos", repository.Name, repository.Commit)
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

func validManifestPath(name string) bool {
	if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || filepath.Ext(name) != ".toml" || strings.ContainsRune(name, '\\') {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.IndexFunc(component, unicode.IsControl) >= 0 {
			return false
		}
	}
	return true
}

func readRegularAt(base, name string) ([]byte, error) {
	if !validManifestPath(name) {
		return nil, errors.New("invalid manifest path")
	}
	directory, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { unix.Close(directory) }()
	components := strings.Split(name, "/")
	for _, component := range components[:len(components)-1] {
		next, openErr := unix.Openat(directory, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, openErr
		}
		unix.Close(directory)
		directory = next
	}
	fd, err := unix.Openat(directory, components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "manifest")
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(file)
}
