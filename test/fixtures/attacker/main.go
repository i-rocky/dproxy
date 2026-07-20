package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type result struct {
	ProjectWrite, HostCanaryRead, HostEnvRead, DockerSocketPresent bool
	Probes                                                         map[string]bool
	GoRoutines                                                     int
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "exit-37":
			os.Exit(37)
		case "terminal-size":
			deadline := time.Now().Add(5 * time.Second)
			for {
				ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				if ws.Row == 33 && ws.Col == 111 {
					fmt.Printf("%d %d\n", ws.Row, ws.Col)
					return
				}
				if time.Now().After(deadline) {
					fmt.Printf("%d %d\n", ws.Row, ws.Col)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		case "wait-term":
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGTERM)
			fmt.Println("ready")
			<-ch
			os.Exit(42)
		case "child-wait":
			select {}
		case "pids-limit":
			var children []*exec.Cmd
			for i := 0; i < 256; i++ {
				child := exec.Command("/attacker", "child-wait")
				if err := child.Start(); err != nil {
					for _, running := range children {
						_ = running.Process.Kill()
						_, _ = running.Process.Wait()
					}
					os.Exit(73)
				}
				children = append(children, child)
			}
			for _, running := range children {
				_ = running.Process.Kill()
				_, _ = running.Process.Wait()
			}
			return
		case "memory-limit":
			var allocations [][]byte
			for {
				block := make([]byte, 8<<20)
				for i := range block {
					block[i] = byte(i)
				}
				allocations = append(allocations, block)
			}
		}
	}
	r := result{Probes: map[string]bool{}, GoRoutines: runtime.NumGoroutine()}
	r.ProjectWrite = os.WriteFile("/workspace/attacker-write", []byte("isolated\n"), 0600) == nil
	hostCanary := os.Getenv("ATTACK_HOST_CANARY_PATH")
	if hostCanary == "" {
		hostCanary = "/host-canary"
	}
	_, err := os.ReadFile(hostCanary)
	r.HostCanaryRead = err == nil
	hostProc := os.Getenv("ATTACK_HOST_PROC_PATH")
	if hostProc == "" {
		hostProc = "/host-proc/1/environ"
	}
	_, err = os.ReadFile(hostProc)
	if data, readErr := os.ReadFile(hostProc); readErr == nil {
		marker := os.Getenv("ATTACK_HOST_PROC_MARKER")
		for _, arg := range os.Args[1:] {
			if strings.HasPrefix(arg, "--host-proc-marker=") {
				decoded, decodeErr := hex.DecodeString(strings.TrimPrefix(arg, "--host-proc-marker="))
				if decodeErr == nil {
					marker = string(decoded)
				}
			}
		}
		r.HostEnvRead = marker != "" && strings.Contains(string(data), marker)
	}
	connection, err := net.DialTimeout("unix", "/var/run/docker.sock", 200*time.Millisecond)
	if err == nil {
		r.DockerSocketPresent = true
		connection.Close()
	}
	client := &http.Client{Timeout: 400 * time.Millisecond}
	for _, key := range []string{"PUBLIC", "PRIVATE", "METADATA", "IPV6", "REBIND", "CROSS", "ALLOWED_TWO"} {
		endpoint := os.Getenv("ATTACK_" + key)
		if endpoint == "" {
			continue
		}
		response, requestErr := client.Get(endpoint)
		r.Probes[key] = requestErr == nil
		if response != nil {
			response.Body.Close()
		}
	}
	if alternate := os.Getenv("ATTACK_ALT_DNS"); alternate != "" {
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", alternate)
		}}
		_, lookupErr := resolver.LookupHost(context.Background(), "one.test")
		r.Probes["ALT_DNS"] = lookupErr == nil
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
