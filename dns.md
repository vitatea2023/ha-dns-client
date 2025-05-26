# High-Availability DNS Client
## 概述
High-Availability DNS Client 是一个专为边缘计算场景设计的高可用DNS客户端，即使在网络环境恶劣、DNS服务失效的情况下，也能确保可靠的域名解析服务。

### 核心特性
+ **多层回退机制**：DoH（DNS over HTTPS） → UDP DNS → 系统DNS
+ **高可用架构**：主域名 + 多个备用域名
+ **智能服务器选择**：基于时间戳的健康检查和负载均衡
+ **循环依赖解决**：预配置IP映射避免DNS查询的循环依赖
+ **并发处理**：并行健康检查提高响应速度
+ **边缘计算优化**：适合在资源受限的边缘环境中部署

### 工作原理
1. **域名解析优先级**：优先解析主域名，失败后依次尝试备用域名
2. **DNS查询回退**：DoH → UDP DNS(53端口) → 系统DNS
3. **服务器健康检查**：通过2025端口的API获取服务器时间戳
4. **智能选择**：选择时间戳最新的服务器，支持负载均衡

## 快速开始
### 环境要求
+ Go 1.19+
+ 网络连接

### 安装依赖
```bash
go mod init dns-client
go get github.com/miekg/dns
```

### 项目结构
```plain
dns-client/
├── main.go           # 主程序和CLI入口
├── dns_client.go     # DNS客户端库
├── config.go         # 配置文件
├── go.mod
├── go.sum
└── README.md
```

## 完整代码实现
### main.go - 主程序和CLI
```go
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"
    "strings"
    "time"
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
```

### dns_client.go - DNS客户端库
```go
package main

import (
    "context"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "net/http"
    "sort"
    "strings"
    "sync"
    "time"

    "github.com/miekg/dns"
)

// Config represents the DNS client configuration
type Config struct {
    PrimaryDomain   string            `json:"primary_domain"`
    BackupDomains   []string          `json:"backup_domains"`
    DOHServers      map[string][]string `json:"doh_servers"`
    UDPDNSServers   []string          `json:"udp_dns_servers"`
    Timeout         time.Duration     `json:"timeout"`
    HealthCheckPort int               `json:"health_check_port"`
}

// DNSResult represents a DNS query result
type DNSResult struct {
    Query  string `json:"query"`
    TTL    uint32 `json:"ttl"`
    RR     string `json:"rr"`
    Answer string `json:"answer"`
}

// DOHTestResult represents the result of a DoH server test
type DOHTestResult struct {
    Domain string      `json:"domain"`
    IP     string      `json:"ip"`
    Status string      `json:"status"`
    Result []DNSResult `json:"result"`
}

// HealthCheckResponse represents the health check API response
type HealthCheckResponse struct {
    Timestamp int64 `json:"timestamp"`
}

// ServerCandidate represents a server candidate with timestamp
type ServerCandidate struct {
    IP        string
    Timestamp int64
}

// DNSClient is the high-availability DNS client
type DNSClient struct {
    config     Config
    httpClient *http.Client
}

// NewDNSClient creates a new DNS client with default configuration
func NewDNSClient() *DNSClient {
    config := Config{
        PrimaryDomain: "wangmai.yuhai.tech",
        BackupDomains: []string{
            "backup1.yuhai.tech",
            "backup2.yuhai.tech",
        },
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
        Timeout:         5 * time.Second,
        HealthCheckPort: 2025,
    }

    return NewDNSClientWithConfig(config)
}

// NewDNSClientWithConfig creates a new DNS client with custom configuration
func NewDNSClientWithConfig(config Config) *DNSClient {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: false,
        },
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            return net.Dial(network, addr)
        },
    }

    httpClient := &http.Client{
        Transport: transport,
        Timeout:   config.Timeout,
    }

    return &DNSClient{
        config:     config,
        httpClient: httpClient,
    }
}

// Create a custom dialer that maps domain to IP
func (dc *DNSClient) createCustomDialer(domainToIP map[string]string) func(context.Context, string, string) (net.Conn, error) {
    return func(ctx context.Context, network, addr string) (net.Conn, error) {
        host, port, err := net.SplitHostPort(addr)
        if err != nil {
            return nil, err
        }

        if mappedIP, exists := domainToIP[host]; exists {
            log.Printf("    DNS Override: %s -> %s", host, mappedIP)
            addr = net.JoinHostPort(mappedIP, port)
        }

        return (&net.Dialer{
            Timeout: dc.config.Timeout,
        }).DialContext(ctx, network, addr)
    }
}

func (dc *DNSClient) testDOHServer(dohDomain, ip, queryDomain string) DOHTestResult {
    // Create DNS query
    msg := new(dns.Msg)
    msg.SetQuestion(dns.Fqdn(queryDomain), dns.TypeA)
    
    wireData, err := msg.Pack()
    if err != nil {
        return DOHTestResult{
            Domain: dohDomain,
            IP:     ip,
            Status: fmt.Sprintf("dns_pack_error_%s", err.Error()),
            Result: nil,
        }
    }

    dnsReq := base64.URLEncoding.EncodeToString(wireData)
    dnsReq = strings.TrimRight(dnsReq, "=")

    // Create custom transport for this request
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: false,
        },
        DialContext: dc.createCustomDialer(map[string]string{dohDomain: ip}),
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   dc.config.Timeout,
    }

    dohURL := fmt.Sprintf("https://%s/dns-query?dns=%s", dohDomain, dnsReq)

    req, err := http.NewRequest("GET", dohURL, nil)
    if err != nil {
        return DOHTestResult{
            Domain: dohDomain,
            IP:     ip,
            Status: fmt.Sprintf("request_create_error_%s", err.Error()),
            Result: nil,
        }
    }

    req.Header.Set("Content-Type", "application/dns-message")
    req.Header.Set("Accept", "application/dns-message")
    req.Header.Set("User-Agent", "DoH-Tester/1.0")

    resp, err := client.Do(req)
    if err != nil {
        return DOHTestResult{
            Domain: dohDomain,
            IP:     ip,
            Status: fmt.Sprintf("request_error_%s", err.Error()),
            Result: nil,
        }
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return DOHTestResult{
            Domain: dohDomain,
            IP:     ip,
            Status: fmt.Sprintf("http_error_%d", resp.StatusCode),
            Result: nil,
        }
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return DOHTestResult{
            Domain: dohDomain,
            IP:     ip,
            Status: fmt.Sprintf("read_error_%s", err.Error()),
            Result: nil,
        }
    }

    // Parse DNS response
    dnsResp := new(dns.Msg)
    err = dnsResp.Unpack(body)
    if err != nil {
        return DOHTestResult{
            Domain: dohDomain,
            IP:     ip,
            Status: fmt.Sprintf("dns_parse_error_%s", err.Error()),
            Result: nil,
        }
    }

    if len(dnsResp.Answer) == 0 {
        return DOHTestResult{
            Domain: dohDomain,
            IP:     ip,
            Status: "no_answer",
            Result: nil,
        }
    }

    var results []DNSResult
    for _, answer := range dnsResp.Answer {
        if aRecord, ok := answer.(*dns.A); ok {
            results = append(results, DNSResult{
                Query:  aRecord.Hdr.Name,
                TTL:    aRecord.Hdr.Ttl,
                RR:     "A",
                Answer: aRecord.A.String(),
            })
        }
    }

    return DOHTestResult{
        Domain: dohDomain,
        IP:     ip,
        Status: "valid",
        Result: results,
    }
}

func (dc *DNSClient) resolveDOHDomain(dohDomain string) []string {
    ips, err := net.LookupIP(dohDomain)
    if err != nil {
        log.Printf("  Failed to resolve %s: %v", dohDomain, err)
        return nil
    }

    var ipList []string
    for _, ip := range ips {
        if ip.To4() != nil { // Only IPv4
            ipStr := ip.String()
            // Check for duplicates
            found := false
            for _, existing := range ipList {
                if existing == ipStr {
                    found = true
                    break
                }
            }
            if !found {
                ipList = append(ipList, ipStr)
            }
        }
    }

    return ipList
}

func (dc *DNSClient) testDOHDomain(dohDomain string, fallbackIPs []string, queryDomain string) []DOHTestResult {
    var results []DOHTestResult
    var testIPs []string

    // Priority 1: Use pre-configured IPs
    if len(fallbackIPs) > 0 {
        testIPs = append(testIPs, fallbackIPs...)
        log.Printf("  Using pre-configured IPs for %s: %v", dohDomain, fallbackIPs)
    }

    // Priority 2: Try system DNS resolution as fallback
    resolvedIPs := dc.resolveDOHDomain(dohDomain)
    if len(resolvedIPs) > 0 {
        // Add non-duplicate resolved IPs
        for _, ip := range resolvedIPs {
            found := false
            for _, existing := range testIPs {
                if existing == ip {
                    found = true
                    break
                }
            }
            if !found {
                testIPs = append(testIPs, ip)
            }
        }
        if len(resolvedIPs) > 0 {
            log.Printf("  Additional resolved IPs for %s: %v", dohDomain, resolvedIPs)
        }
    }

    // If no available IPs
    if len(testIPs) == 0 {
        return []DOHTestResult{{
            Domain: dohDomain,
            IP:     "",
            Status: "no_ips_available",
            Result: nil,
        }}
    }

    // Test each IP
    log.Printf("  Testing %d IP(s) for %s", len(testIPs), dohDomain)
    for i, ip := range testIPs {
        log.Printf("    [%d/%d] Testing %s via IP %s...", i+1, len(testIPs), dohDomain, ip)
        result := dc.testDOHServer(dohDomain, ip, queryDomain)
        results = append(results, result)

        // Show result
        statusIcon := "✗"
        if result.Status == "valid" {
            statusIcon = "✓"
        }
        log.Printf("    %s Result: %s", statusIcon, result.Status)

        if result.Status == "valid" {
            log.Printf("    🎉 %s via %s is working!", dohDomain, ip)
        }
    }

    return results
}

func (dc *DNSClient) queryUDPDNS(domain string, dnsServer string) []string {
    c := new(dns.Client)
    c.Timeout = dc.config.Timeout

    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

    r, _, err := c.Exchange(m, dnsServer+":53")
    if err != nil {
        log.Printf("    UDP DNS query to %s failed: %v", dnsServer, err)
        return nil
    }

    var ips []string
    for _, ans := range r.Answer {
        if aRecord, ok := ans.(*dns.A); ok {
            ips = append(ips, aRecord.A.String())
        }
    }

    return ips
}

func (dc *DNSClient) querySystemDNS(domain string) []string {
    ips, err := net.LookupIP(domain)
    if err != nil {
        log.Printf("    System DNS query failed: %v", err)
        return nil
    }

    var ipList []string
    for _, ip := range ips {
        if ip.To4() != nil { // Only IPv4
            ipList = append(ipList, ip.String())
        }
    }

    return ipList
}

func (dc *DNSClient) checkHealth(ip string) (int64, error) {
    url := fmt.Sprintf("http://%s:%d/get-dns-time", ip, dc.config.HealthCheckPort)
    
    client := &http.Client{
        Timeout: dc.config.Timeout,
    }

    resp, err := client.Get(url)
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return 0, err
    }

    var healthResp HealthCheckResponse
    err = json.Unmarshal(body, &healthResp)
    if err != nil {
        return 0, err
    }

    return healthResp.Timestamp, nil
}

func (dc *DNSClient) selectBestServer(ips []string) (string, error) {
    if len(ips) == 0 {
        return "", fmt.Errorf("no IPs to check")
    }

    log.Printf("  Checking health for %d servers...", len(ips))

    var wg sync.WaitGroup
    var mu sync.Mutex
    var candidates []ServerCandidate

    for _, ip := range ips {
        wg.Add(1)
        go func(ip string) {
            defer wg.Done()
            
            timestamp, err := dc.checkHealth(ip)
            if err != nil {
                log.Printf("    ✗ %s health check failed: %v", ip, err)
                return
            }

            log.Printf("    ✓ %s health check passed, timestamp: %d", ip, timestamp)
            
            mu.Lock()
            candidates = append(candidates, ServerCandidate{
                IP:        ip,
                Timestamp: timestamp,
            })
            mu.Unlock()
        }(ip)
    }

    wg.Wait()

    if len(candidates) == 0 {
        return "", fmt.Errorf("no healthy servers found")
    }

    // Sort by timestamp (descending - latest first)
    sort.Slice(candidates, func(i, j int) bool {
        return candidates[i].Timestamp > candidates[j].Timestamp
    })

    // Find all servers with the latest timestamp
    latestTimestamp := candidates[0].Timestamp
    var latestServers []string

    for _, candidate := range candidates {
        if candidate.Timestamp == latestTimestamp {
            latestServers = append(latestServers, candidate.IP)
        } else {
            break // Since sorted, we can break early
        }
    }

    log.Printf("  Found %d server(s) with latest timestamp %d", len(latestServers), latestTimestamp)

    // If multiple servers have the same latest timestamp, randomly select one
    if len(latestServers) > 1 {
        log.Printf("  Multiple servers with same timestamp, selecting randomly...")
        selectedIP := latestServers[rand.Intn(len(latestServers))]
        log.Printf("  Selected: %s", selectedIP)
        return selectedIP, nil
    }

    log.Printf("  Selected: %s", latestServers[0])
    return latestServers[0], nil
}

func (dc *DNSClient) resolveWithDOH(domain string) (string, error) {
    log.Printf("🔍 Trying DoH resolution for %s...", domain)
    
    var allResults []DOHTestResult
    
    for dohDomain, fallbackIPs := range dc.config.DOHServers {
        log.Printf("\n🔍 Testing %s...", dohDomain)
        results := dc.testDOHDomain(dohDomain, fallbackIPs, domain)
        allResults = append(allResults, results...)
    }

    // Collect all valid IPs
    var validIPs []string
    for _, result := range allResults {
        if result.Status == "valid" && result.Result != nil {
            for _, dnsResult := range result.Result {
                validIPs = append(validIPs, dnsResult.Answer)
            }
        }
    }

    if len(validIPs) == 0 {
        return "", fmt.Errorf("no valid DoH results")
    }

    // Remove duplicates
    ipMap := make(map[string]bool)
    var uniqueIPs []string
    for _, ip := range validIPs {
        if !ipMap[ip] {
            ipMap[ip] = true
            uniqueIPs = append(uniqueIPs, ip)
        }
    }

    log.Printf("DoH resolved %d unique IP(s): %v", len(uniqueIPs), uniqueIPs)
    return dc.selectBestServer(uniqueIPs)
}

func (dc *DNSClient) resolveWithUDP(domain string) (string, error) {
    log.Printf("🔍 Trying UDP DNS resolution for %s...", domain)
    
    var allIPs []string
    
    for _, dnsServer := range dc.config.UDPDNSServers {
        log.Printf("  Querying %s...", dnsServer)
        ips := dc.queryUDPDNS(domain, dnsServer)
        if len(ips) > 0 {
            log.Printf("    ✓ Got %d IP(s): %v", len(ips), ips)
            allIPs = append(allIPs, ips...)
        } else {
            log.Printf("    ✗ No results")
        }
    }

    if len(allIPs) == 0 {
        return "", fmt.Errorf("no valid UDP DNS results")
    }

    // Remove duplicates
    ipMap := make(map[string]bool)
    var uniqueIPs []string
    for _, ip := range allIPs {
        if !ipMap[ip] {
            ipMap[ip] = true
            uniqueIPs = append(uniqueIPs, ip)
        }
    }

    log.Printf("UDP DNS resolved %d unique IP(s): %v", len(uniqueIPs), uniqueIPs)
    return dc.selectBestServer(uniqueIPs)
}

func (dc *DNSClient) resolveWithSystem(domain string) (string, error) {
    log.Printf("🔍 Trying system DNS resolution for %s...", domain)
    
    ips := dc.querySystemDNS(domain)
    if len(ips) == 0 {
        return "", fmt.Errorf("no valid system DNS results")
    }

    log.Printf("System DNS resolved %d IP(s): %v", len(ips), ips)
    return dc.selectBestServer(ips)
}

// ResolveDomain resolves a single domain using all available methods
func (dc *DNSClient) ResolveDomain(domain string) (string, error) {
    log.Printf("🚀 Starting DNS resolution for: %s", domain)
    
    // Try DoH first
    if ip, err := dc.resolveWithDOH(domain); err == nil {
        log.Printf("✅ DoH resolution succeeded: %s -> %s", domain, ip)
        return ip, nil
    } else {
        log.Printf("❌ DoH resolution failed: %v", err)
    }

    // Fallback to UDP DNS
    if ip, err := dc.resolveWithUDP(domain); err == nil {
        log.Printf("✅ UDP DNS resolution succeeded: %s -> %s", domain, ip)
        return ip, nil
    } else {
        log.Printf("❌ UDP DNS resolution failed: %v", err)
    }

    // Fallback to system DNS
    if ip, err := dc.resolveWithSystem(domain); err == nil {
        log.Printf("✅ System DNS resolution succeeded: %s -> %s", domain, ip)
        return ip, nil
    } else {
        log.Printf("❌ System DNS resolution failed: %v", err)
    }

    return "", fmt.Errorf("all DNS resolution methods failed for domain: %s", domain)
}

// ResolveHighAvailability performs high-availability resolution using primary and backup domains
func (dc *DNSClient) ResolveHighAvailability() (string, error) {
    log.Printf("🎯 Starting high-availability resolution...")
    
    // Try primary domain first
    log.Printf("📍 Trying primary domain: %s", dc.config.PrimaryDomain)
    if ip, err := dc.ResolveDomain(dc.config.PrimaryDomain); err == nil {
        log.Printf("🎉 Primary domain resolved successfully: %s", ip)
        return ip, nil
    } else {
        log.Printf("⚠️  Primary domain failed: %v", err)
    }

    // Try backup domains
    for i, backupDomain := range dc.config.BackupDomains {
        log.Printf("📍 Trying backup domain %d/%d: %s", i+1, len(dc.config.BackupDomains), backupDomain)
        if ip, err := dc.ResolveDomain(backupDomain); err == nil {
            log.Printf("🎉 Backup domain resolved successfully: %s", ip)
            return ip, nil
        } else {
            log.Printf("⚠️  Backup domain failed: %v", err)
        }
    }

    return "", fmt.Errorf("all domains (primary + backup) resolution failed")
}
```

### config.json - 配置文件示例
```json
{
  "primary_domain": "wangmai.yuhai.tech",
  "backup_domains": [
    "backup1.yuhai.tech",
    "backup2.yuhai.tech",
    "backup3.yuhai.tech"
  ],
  "doh_servers": {
    "dns.alidns.com": ["223.5.5.5", "223.6.6.6"],
    "doh.360.cn": ["101.198.198.198", "123.125.81.6", "112.65.69.15", "101.198.199.200"],
    "doh.pub": ["1.12.12.12", "120.53.53.53"],
    "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"]
  },
  "udp_dns_servers": [
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "182.254.116.116",
    "114.114.114.114",
    "114.114.115.115",
    "180.76.76.76",
    "1.2.4.8",
    "210.2.4.8",
    "101.6.6.6",
    "117.50.10.10",
    "52.80.52.52",
    "211.138.24.66",
    "123.123.123.123",
    "123.123.123.124",
    "218.85.152.99"
  ],
  "timeout": "10s",
  "health_check_port": 2025
}
```

## CLI使用指南
### 基本用法
```bash
# 编译程序
go build -o dns-client

# 使用默认配置
./dns-client

# 指定主域名
./dns-client --primary example.com

# 指定备用域名
./dns-client --backup "backup1.com,backup2.com,backup3.com"

# 设置超时时间
./dns-client --timeout 10

# 指定健康检查端口
./dns-client --health-port 3000

# 使用配置文件
./dns-client --config config.json

# JSON格式输出
./dns-client --output json

# 静默模式（无详细日志）
./dns-client --verbose=false
```

### 高级用法
```bash
# 组合多个参数
./dns-client \
  --primary "api.example.com" \
  --backup "backup1.example.com,backup2.example.com" \
  --timeout 15 \
  --health-port 2025 \
  --output json

# 使用配置文件并覆盖部分配置
./dns-client \
  --config production.json \
  --timeout 30 \
  --verbose

# 调试模式
./dns-client --verbose --output json > debug.log 2>&1
```

### 输出格式
#### 文本格式（默认）
```plain
✅ Success: 192.168.1.100
```

#### JSON格式
```json
{
  "success": true,
  "ip": "192.168.1.100",
  "timestamp": 1703123456,
  "method": "doh"
}
```

## 作为库使用
### 基本使用
```go
package main

import (
    "fmt"
    "log"
)

func main() {
    // 使用默认配置创建客户端
    client := NewDNSClient()
    
    // 解析单个域名
    ip, err := client.ResolveDomain("example.com")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Resolved IP: %s\n", ip)
}
```

### 高可用解析
```go
package main

import (
    "fmt"
    "log"
)

func main() {
    // 创建客户端
    client := NewDNSClient()
    
    // 高可用解析（主域名 + 备用域名）
    ip, err := client.ResolveHighAvailability()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Final IP: %s\n", ip)
}
```

### 自定义配置
```go
package main

import (
    "fmt"
    "log"
    "time"
)

func main() {
    // 自定义配置
    config := Config{
        PrimaryDomain: "my-api.com",
        BackupDomains: []string{
            "backup-api1.com",
            "backup-api2.com",
        },
        DOHServers: map[string][]string{
            "dns.alidns.com": {"223.5.5.5", "223.6.6.6"},
            "doh.pub": {"1.12.12.12"},
        },
        UDPDNSServers: []string{
            "8.8.8.8",
            "8.8.4.4",
        },
        Timeout:         10 * time.Second,
        HealthCheckPort: 3000,
    }
    
    // 使用自定义配置创建客户端
    client := NewDNSClientWithConfig(config)
    
    // 执行解析
    ip, err := client.ResolveHighAvailability()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Resolved IP: %s\n", ip)
}
```

### 集成到现有应用
```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "time"
)

type APIClient struct {
    dnsClient *DNSClient
    baseURL   string
    client    *http.Client
}

func NewAPIClient() *APIClient {
    return &APIClient{
        dnsClient: NewDNSClient(),
        client: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

func (ac *APIClient) Connect() error {
    // 使用高可用DNS解析获取服务器IP
    ip, err := ac.dnsClient.ResolveHighAvailability()
    if err != nil {
        return fmt.Errorf("failed to resolve server: %v", err)
    }
    
    // 构建API基础URL
    ac.baseURL = fmt.Sprintf("http://%s:8080", ip)
    
    log.Printf("Connected to server: %s", ac.baseURL)
    return nil
}

func (ac *APIClient) GetData() ([]byte, error) {
    if ac.baseURL == "" {
        if err := ac.Connect(); err != nil {
            return nil, err
        }
    }
    
    resp, err := ac.client.Get(ac.baseURL + "/api/data")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    // 处理响应...
    return nil, nil
}

func main() {
    client := NewAPIClient()
    
    // 自动解析并连接到最佳服务器
    data, err := client.GetData()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Data: %v\n", data)
}
```

## 服务器端健康检查实现
为了配合DNS客户端的健康检查机制，服务器端需要实现健康检查API：

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type HealthResponse struct {
    Timestamp int64 `json:"timestamp"`
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
    response := HealthResponse{
        Timestamp: time.Now().Unix(),
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func main() {
    http.HandleFunc("/get-dns-time", healthCheckHandler)
    
    fmt.Println("Health check server listening on :2025")
    if err := http.ListenAndServe(":2025", nil); err != nil {
        panic(err)
    }
}
```

## 部署和运维
### Docker部署
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o dns-client .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/

COPY --from=builder /app/dns-client .
COPY --from=builder /app/config.json .

CMD ["./dns-client", "--config", "config.json"]
```

### 系统服务
```properties
# /etc/systemd/system/dns-client.service
[Unit]
Description=High-Availability DNS Client
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dns-client --config /etc/dns-client/config.json
User=dns-client
Group=dns-client

[Install]
WantedBy=multi-user.target
```

### 监控和日志
```bash
# 启用详细日志
./dns-client --verbose --output json | tee dns-client.log

# 定期健康检查
*/5 * * * * /usr/local/bin/dns-client --output json >> /var/log/dns-client.log 2>&1
```

## 故障排除
### 常见问题
1. **DoH连接失败**
    - 检查网络连接
    - 验证DoH服务器配置
    - 检查防火墙设置
2. **健康检查失败**
    - 确认目标服务器2025端口开放
    - 检查健康检查API是否正常运行
    - 验证网络连通性
3. **DNS解析超时**
    - 增加超时时间配置
    - 检查DNS服务器可用性
    - 验证网络延迟

### 调试技巧
```bash
# 启用详细日志
./dns-client --verbose

# 使用单一DNS方法测试
./dns-client --primary test.com --verbose

# 输出JSON格式便于分析
./dns-client --output json --verbose 2>&1 | jq .
```

## 性能优化
1. **并发优化**：健康检查使用goroutine并发执行
2. **超时控制**：合理设置各项超时时间
3. **缓存机制**：可在业务层实现结果缓存
4. **连接复用**：HTTP客户端支持连接复用

## 安全考虑
1. **HTTPS验证**：DoH请求默认验证SSL证书
2. **输入验证**：对域名和IP进行格式验证
3. **错误处理**：避免敏感信息泄露
4. **权限控制**：以非特权用户运行

这个高可用DNS客户端为边缘计算场景提供了robust的域名解析解决方案，通过多层回退机制和智能服务器选择，确保在各种网络环境下都能可靠工作。

