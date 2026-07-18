package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
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
		}
	}
	r := result{Probes: map[string]bool{}, GoRoutines: runtime.NumGoroutine()}
	r.ProjectWrite = os.WriteFile("/workspace/attacker-write", []byte("isolated\n"), 0600) == nil
	_, err := os.ReadFile("/host-canary")
	r.HostCanaryRead = err == nil
	_, err = os.ReadFile("/host-proc/1/environ")
	r.HostEnvRead = err == nil
	connection, err := net.DialTimeout("unix", "/var/run/docker.sock", 200*time.Millisecond)
	if err == nil {
		r.DockerSocketPresent = true
		connection.Close()
	}
	client := &http.Client{Timeout: 400 * time.Millisecond}
	for _, key := range []string{"PUBLIC", "PRIVATE", "METADATA", "IPV6", "REBIND"} {
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
	_ = json.NewEncoder(os.Stdout).Encode(r)
}
