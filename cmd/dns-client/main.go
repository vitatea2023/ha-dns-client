package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "strings"
    "time"
    
    . "github.com/vitatea2023/ha-dns-client"
)

type CLIConfig struct {
    PrimaryDomain   *string
    BackupDomains   *string
    Timeout         *int
    HealthPort      *int
    ConfigFile      *string
    Verbose         *bool
    OutputFormat    *string
}

func parseCLIArgs() CLIConfig {
    config := CLIConfig{
        PrimaryDomain: flag.String("primary", "ssh.example.com", "Primary domain to resolve"),
        BackupDomains: flag.String("backup", "backup1.example.com,backup2.example.com", "Backup domains (comma-separated)"),
        Timeout:       flag.Int("timeout", 5, "Timeout in seconds"),
        HealthPort:    flag.Int("health-port", 2025, "Health check port"),
        ConfigFile:    flag.String("config", "", "Path to JSON config file"),
        Verbose:       flag.Bool("verbose", true, "Enable verbose logging"),
        OutputFormat:  flag.String("output", "text", "Output format: text, json"),
    }

    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "High-Availability DNS Client\n\n")
        fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "Options:\n")
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "\nExamples:\n")
        fmt.Fprintf(os.Stderr, "  %s --primary example.com --verbose\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "  %s --config config.json --output json\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "  %s --backup \"backup1.com,backup2.com\" --timeout 10\n", os.Args[0])
    }

    flag.Parse()
    return config
}

func loadConfigFromFile(filename string) (*Config, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var config Config
    decoder := json.NewDecoder(file)
    err = decoder.Decode(&config)
    if err != nil {
        return nil, err
    }

    return &config, nil
}

func createConfigFromCLI(cliConfig CLIConfig) *Config {
    config := &Config{
        PrimaryDomain: *cliConfig.PrimaryDomain,
        BackupDomains: strings.Split(*cliConfig.BackupDomains, ","),
        DOHServers: map[string][]string{
            "dns.alidns.com": {"223.5.5.5", "223.6.6.6"},
            "doh.360.cn":     {"101.198.198.198", "123.125.81.6", "112.65.69.15", "101.198.199.200"},
            "doh.pub":        {"1.12.12.12", "120.53.53.53"},
        },
        UDPDNSServers: []string{
            "223.5.5.5", "223.6.6.6", "119.29.29.29", "182.254.116.116",
            "114.114.114.114", "114.114.115.115", "180.76.76.76", "1.2.4.8",
            "210.2.4.8", "101.6.6.6", "117.50.10.10", "52.80.52.52",
            "211.138.24.66", "123.123.123.123", "123.123.123.124", "218.85.152.99",
        },
        Timeout:         time.Duration(*cliConfig.Timeout) * time.Second,
        HealthCheckPort: *cliConfig.HealthPort,
    }

    // Clean up backup domains
    var cleanBackups []string
    for _, domain := range config.BackupDomains {
        domain = strings.TrimSpace(domain)
        if domain != "" {
            cleanBackups = append(cleanBackups, domain)
        }
    }
    config.BackupDomains = cleanBackups

    return config
}

type Result struct {
    Success   bool   `json:"success"`
    IP        string `json:"ip,omitempty"`
    Error     string `json:"error,omitempty"`
    Timestamp int64  `json:"timestamp"`
    Method    string `json:"method,omitempty"`
}

func outputResult(result Result, format string) {
    switch format {
    case "json":
        jsonData, _ := json.MarshalIndent(result, "", "  ")
        fmt.Println(string(jsonData))
    default:
        if result.Success {
            fmt.Printf("✅ Success: %s\n", result.IP)
        } else {
            fmt.Printf("❌ Failed: %s\n", result.Error)
        }
    }
}

func main() {
    cliConfig := parseCLIArgs()

    // Configure logging
    if !*cliConfig.Verbose {
        log.SetOutput(os.Stderr)
    }

    // Load configuration
    var config *Config
    var err error

    if *cliConfig.ConfigFile != "" {
        config, err = loadConfigFromFile(*cliConfig.ConfigFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("📄 Loaded configuration from: %s\n", *cliConfig.ConfigFile)
    } else {
        config = createConfigFromCLI(cliConfig)
    }

    // Create DNS client
    client := NewDNSClientWithConfig(*config)

    if *cliConfig.Verbose {
        fmt.Printf("🚀 High-Availability DNS Client\n")
        fmt.Printf("📋 Primary Domain: %s\n", config.PrimaryDomain)
        fmt.Printf("📋 Backup Domains: %v\n", config.BackupDomains)
        fmt.Printf("⏱️  Timeout: %v\n", config.Timeout)
        fmt.Printf("🏥 Health Check Port: %d\n", config.HealthCheckPort)
        fmt.Printf("📊 DoH Servers: %d configured\n", len(config.DOHServers))
        fmt.Printf("📊 UDP DNS Servers: %d configured\n", len(config.UDPDNSServers))
        fmt.Println(strings.Repeat("=", 60))
    }

    // Perform resolution
    start := time.Now()
    finalIP, err := client.ResolveHighAvailability()
    duration := time.Since(start)

    result := Result{
        Timestamp: time.Now().Unix(),
    }

    if err != nil {
        result.Success = false
        result.Error = err.Error()
        outputResult(result, *cliConfig.OutputFormat)
        if *cliConfig.Verbose {
            fmt.Printf("⏱️  Total time: %v\n", duration)
        }
        os.Exit(1)
    }

    result.Success = true
    result.IP = finalIP
    outputResult(result, *cliConfig.OutputFormat)

    if *cliConfig.Verbose {
        fmt.Printf("⏱️  Total time: %v\n", duration)
        fmt.Printf("🔗 Server ready at: %s\n", finalIP)
    }
}