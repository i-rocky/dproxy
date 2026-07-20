package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	addresses := []string{":8080", ":8081"}
	if len(os.Args) == 2 {
		addresses = []string{os.Args[1]}
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "dproxy-fixture") })
	var wg sync.WaitGroup
	if publicIP := os.Getenv("FIXTURE_PUBLIC_IP"); publicIP != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveDNS(publicIP)
		}()
	}
	for _, address := range addresses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := http.ListenAndServe(address, nil); err != nil {
				panic(err)
			}
		}()
	}
	wg.Wait()
}

func serveDNS(publicRaw string) {
	public := netip.MustParseAddr(publicRaw).As4()
	private := netip.MustParseAddr("10.77.0.10").As4()
	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	buffer := make([]byte, 1500)
	for {
		n, peer, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			panic(readErr)
		}
		var parser dnsmessage.Parser
		header, parseErr := parser.Start(buffer[:n])
		if parseErr != nil {
			continue
		}
		question, parseErr := parser.Question()
		if parseErr != nil {
			continue
		}
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true})
		builder.EnableCompression()
		_ = builder.StartQuestions()
		_ = builder.Question(question)
		_ = builder.StartAnswers()
		if question.Type == dnsmessage.TypeA {
			_ = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: public})
			if question.Name.String() == "rebind.test." {
				_ = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: private})
			}
		}
		response, finishErr := builder.Finish()
		if finishErr == nil {
			_, _ = conn.WriteTo(response, peer)
		}
	}
}
