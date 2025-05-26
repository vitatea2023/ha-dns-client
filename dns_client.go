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