package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"strings"
	"os"
	"github.com/projectdiscovery/cdncheck"
)

func main() {
	// uses projectdiscovery endpoint with cached data to avoid ip ban
	// Use cdncheck.New() if you want to scrape each endpoint (don't do it too often or your ip can be blocked)
	client, err := cdncheck.NewWithCache()
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	ip := net.ParseIP(input)
	inputType := "IP"
	if ip == nil {
		// input is not a valid IP address, assume it is a domain and perform a DNS lookup
		ips, err := net.LookupIP(input)
		if err != nil {
			log.Fatal(err)
		}
		ip = ips[0]
		inputType = "DOMAIN"
	}

	found, result, err := client.Check(ip)
	if err != nil {
		log.Fatal(err)
	}

	output := map[string]interface{}{
		"input": input,
		"inputType": inputType,
		"ip":    ip.String(),
		"cdn":   found,
		"service":  result,
	}

	if !found {
		output["service"] = nil
	}

	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	outputFile := os.Args[1]
	f, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.Write(jsonOutput)
	if err != nil {
		log.Fatal(err)
	}
}