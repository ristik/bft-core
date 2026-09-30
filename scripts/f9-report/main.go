package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "", "path to the collector JSON config")
	outputPath := flag.String("out", "-", "output report path, or - for stdout")
	flag.Parse()
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "-config is required")
		os.Exit(2)
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := &httpClient
	result := collect(ctx, cfg, client, time.Now)
	var writer io.Writer = os.Stdout
	var file *os.File
	if *outputPath != "-" {
		file, err = os.Create(*outputPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		writer = file
	}
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	writeErr := enc.Encode(result)
	if file != nil {
		if closeErr := file.Close(); writeErr == nil {
			writeErr = closeErr
		}
	}
	if writeErr != nil {
		fmt.Fprintln(os.Stderr, writeErr)
		os.Exit(2)
	}
	if !result.Complete {
		os.Exit(1)
	}
}

var httpClient = http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("too many redirects")
	}
	return nil
}}
