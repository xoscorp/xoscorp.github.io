package main

import (
	"bufio"
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
	Domain   string
	Output   string
	Threads  int
	Modules  []string
	Result   *ScanResult
	mu       sync.Mutex
	Client   *http.Client
}

func main() {
	banner()

	domain := flag.String("d", "", "Target domain (required)")
	modules := flag.String("m", "s,sqli,xss,ssrf,aes,nuclei", "Modules: s(subdomain),sqli,xss,ssrf,aes(jscrypto),nuclei,s3")
	output := flag.String("o", "scan_results.json", "Output file")
	threads := flag.Int("t", 50, "Number of threads")
	flag.Parse()

	if *domain == "" {
		fmt.Println(ColorRed + "[!] Domain is required. Use -d flag" + ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	scanner := &Scanner{
		Domain:  *domain,
		Output:  *output,
		Threads: *threads,
		Modules: strings.Split(*modules, ","),
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
	fmt.Printf("%s[*] Modules: %s%s\n", ColorCyan, *modules, ColorReset)
	fmt.Printf("%s[*] Threads: %d%s\n\n", ColorCyan, *threads, ColorReset)

	scanner.Run()
}

func banner() {
	fmt.Printf("%s%s", ColorCyan, `
+=================================================================+
|         *UCK* SCANNER v4.0 - GO EDITION                        |
|       High-Quality Vulnerability Hunter                        |
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

func (s *Scanner) mineParameters() {
	fmt.Printf("\n%s%s[+] MODULE: PARAMETER MINING%s\n", ColorBold, ColorBlue, ColorReset)
	fmt.Printf("%s[*] Mining parameters from all live hosts...%s\n", ColorCyan, ColorReset)

	var wg sync.WaitGroup
	paramChan := make(chan Parameter, 1000)

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

	go func() {
		wg.Wait()
		close(paramChan)
	}()

	seen := make(map[string]bool)
	for param := range paramChan {
		key := fmt.Sprintf("%s_%s_%s", param.URL, param.Method, param.ParamName)
		if !seen[key] {
			seen[key] = true
			s.mu.Lock()
			s.Result.Parameters = append(s.Result.Parameters, param)
			s.mu.Unlock()
		}
	}

	fmt.Printf("%s[✓] Mined %d unique parameters%s\n", ColorGreen, len(s.Result.Parameters), ColorReset)

	s.saveParametersToFile()
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

	urlRegex := regexp.MustCompile(`(?:href|src|action)=["']([^"']+\?[^"']+)["']`)
	matches := urlRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, match := range matches {
		if len(match) > 1 {
			fullURL := match[1]

			if strings.Contains(fullURL, "google") ||
				strings.Contains(fullURL, "fonts.") ||
				strings.Contains(fullURL, "cdn.") ||
				strings.Contains(fullURL, "facebook") ||
				strings.Contains(fullURL, "twitter") {
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

							if skipParams[paramName] {
								continue
							}

							if len(paramName) < 2 || regexp.MustCompile(`^\d+$`).MatchString(paramName) {
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

	formRegex := regexp.MustCompile(`<form[^>]*action=["']([^"']*)["'][^>]*>([\s\S]*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) > 2 {
			action := formMatch[1]
			formBody := formMatch[2]

			if strings.Contains(action, "google") ||
				strings.Contains(action, "facebook") ||
				strings.Contains(action, "twitter") {
				continue
			}

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

					if skipParams[paramName] ||
						paramName == "csrf" ||
						paramName == "token" ||
						strings.Contains(paramName, "csrf") {
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

	jsAPIRegex := regexp.MustCompile(`(?:fetch|axios|XMLHttpRequest|\.get|\.post)[^(]*\([^)]*["']([^"']+\?[^"']+)["']`)
	jsMatches := jsAPIRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, jsMatch := range jsMatches {
		if len(jsMatch) > 1 {
			apiURL := jsMatch[1]

			if strings.Contains(apiURL, "google") ||
				strings.Contains(apiURL, "cdn.") {
				continue
			}

			if strings.Contains(apiURL, "?") {
				parts := strings.Split(apiURL, "?")
				if len(parts) == 2 {
					paramPairs := strings.Split(parts[1], "&")
					for _, pair := range paramPairs {
						kv := strings.Split(pair, "=")
						if len(kv) >= 1 {
							paramName := strings.ToLower(strings.TrimSpace(kv[0]))

							if skipParams[paramName] {
								continue
							}

							param := Parameter{
								URL:       url,
								Method:    "GET",
								ParamName: paramName,
								ParamType: "API",
							}

							if highValueParams[paramName] {
								param.ParamType = "API_HIGH_VALUE"
							}

							params = append(params, param)
						}
					}
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

func (s *Scanner) scanXSS() {
	fmt.Printf("\n%s%s[+] MODULE: XSS SCANNING (DALFOX)%s\n", ColorBold, ColorBlue, ColorReset)

	if len(s.Result.Parameters) == 0 {
		fmt.Printf("%s[!] No parameters found to test%s\n", ColorYellow, ColorReset)
		return
	}

	cmd := exec.Command("dalfox", "file", "parameters.txt",
		"-o", "dalfox_results.txt",
		"--silence",
		"--format", "json",
		"--skip-bav",
		"--mining-dict",
		"--skip-mining-all")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s[!] Dalfox error (may not be installed): %v%s\n", ColorYellow, err, ColorReset)
		return
	}

	if len(output) > 0 {
		var results []map[string]interface{}
		if err := json.Unmarshal(output, &results); err == nil {
			for _, result := range results {
				vuln := Vulnerability{
					Type:        "Cross-Site Scripting (XSS)",
					Severity:    "HIGH",
					URL:         fmt.Sprintf("%v", result["url"]),
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
}

func (s *Scanner) scanSQLi() {
	fmt.Printf("\n%s%s[+] MODULE: SQL INJECTION (SQLMAP)%s\n", ColorBold, ColorBlue, ColorReset)

	if len(s.Result.Parameters) == 0 {
		fmt.Printf("%s[!] No parameters found to test%s\n", ColorYellow, ColorReset)
		return
	}

	maxTests := 20
	if len(s.Result.Parameters) < maxTests {
		maxTests = len(s.Result.Parameters)
	}

	for i := 0; i < maxTests; i++ {
		param := s.Result.Parameters[i]
		testURL := fmt.Sprintf("%s?%s=1", param.URL, param.ParamName)

		fmt.Printf("%s[*] Testing: %s%s\n", ColorCyan, testURL, ColorReset)

		cmd := exec.Command("sqlmap",
			"-u", testURL,
			"--batch",
			"--random-agent",
			"--level=1",
			"--risk=1",
			"--threads=10",
			"--technique=BEUSTQ",
			"--output-dir=/tmp/sqlmap",
		)

		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "injectable") {
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
}

func (s *Scanner) scanSSRF() {
	fmt.Printf("\n%s%s[+] MODULE: SSRF SCANNING%s\n", ColorBold, ColorBlue, ColorReset)

	ssrfPayloads := []string{
		"http://127.0.0.1",
		"http://localhost",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]",
		"http://0.0.0.0",
		"file:///etc/passwd",
		"http://metadata.google.internal/computeMetadata/v1/",
	}

	for _, param := range s.Result.Parameters {
		for _, payload := range ssrfPayloads {
			testURL := fmt.Sprintf("%s?%s=%s", param.URL, param.ParamName, payload)

			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := s.Client.Do(req)
			if err == nil {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "ami-id") ||
					strings.Contains(string(body), "instance-id") ||
					strings.Contains(string(body), "root:x:0:0") ||
					strings.Contains(string(body), "Google Cloud") {

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
					fmt.Printf("%s[!] CRITICAL: SSRF found at %s%s\n", ColorRed, param.URL, ColorReset)
					break
				}
			}
		}
	}
}
func (s *Scanner) scanS3Buckets() {
	fmt.Printf("\n%s%s[+] MODULE: CLOUD STORAGE SCANNING (S3 + Azure + GCP)%s\n", ColorBold, ColorBlue, ColorReset)

	bucketNames := s.generateBucketNames()

	fmt.Printf("%s[*] Generated %d potential bucket names%s\n", ColorCyan, len(bucketNames), ColorReset)

	s.scanAWSS3(bucketNames)
	s.scanAzureBlob(bucketNames)
	s.scanGCPStorage(bucketNames)

	fmt.Printf("%s[✓] Found %d cloud storage buckets/containers%s\n", ColorGreen, len(s.Result.S3Buckets), ColorReset)
}

func (s *Scanner) scanAWSS3(bucketNames []string) {
	fmt.Printf("\n%s[*] Scanning AWS S3 buckets...%s\n", ColorCyan, ColorReset)

	var wg sync.WaitGroup
	results := make(chan S3Bucket, len(bucketNames))
	semaphore := make(chan struct{}, 20)

	for _, bucketName := range bucketNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			bucket := s.checkAWSS3Bucket(name)
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

		if bucket.Takeover {
			vuln := Vulnerability{
				Type:        "AWS S3 Bucket Takeover",
				Severity:    "CRITICAL",
				URL:         fmt.Sprintf("s3://%s", bucket.Name),
				Evidence:    "Bucket does not exist but DNS points to it - can be claimed!",
				Tool:        "s3-scanner",
				Timestamp:   time.Now(),
				Remediation: "Remove DNS record or create the bucket immediately",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] CRITICAL: S3 Takeover possible: %s%s\n", ColorRed, bucket.Name, ColorReset)
		} else if bucket.Public || bucket.Listable {
			vuln := Vulnerability{
				Type:        "Exposed AWS S3 Bucket",
				Severity:    "HIGH",
				URL:         fmt.Sprintf("s3://%s", bucket.Name),
				Evidence:    fmt.Sprintf("Public: %v, Listable: %v, Writable: %v", bucket.Public, bucket.Listable, bucket.Writable),
				Tool:        "s3-scanner",
				Timestamp:   time.Now(),
				Remediation: "Enable bucket encryption and block public access",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] S3 Bucket exposed: %s (Public: %v, Listable: %v)%s\n",
				ColorYellow, bucket.Name, bucket.Public, bucket.Listable, ColorReset)
		} else {
			fmt.Printf("%s[*] S3 Bucket found (private): %s%s\n", ColorCyan, bucket.Name, ColorReset)
		}
	}
}

func (s *Scanner) checkAWSS3Bucket(bucketName string) S3Bucket {
	bucket := S3Bucket{
		Name:       bucketName,
		BucketType: "s3",
	}

	regions := []string{"us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"}

	for _, region := range regions {
		url := fmt.Sprintf("https://%s.s3.amazonaws.com", bucketName)
		if region != "us-east-1" {
			url = fmt.Sprintf("https://%s.s3-%s.amazonaws.com", bucketName, region)
		}

		resp, err := s.Client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		bucket.Region = region

		if resp.StatusCode == 404 {
			testURL := fmt.Sprintf("https://%s.%s.s3.amazonaws.com", bucketName, s.Domain)
			testResp, err := s.Client.Head(testURL)
			if err == nil {
				testResp.Body.Close()
				if testResp.StatusCode == 404 {
					bucket.Takeover = true
					bucket.Name = bucketName
					return bucket
				}
			}
			continue
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

			testObj := url + "/test-write-" + time.Now().Format("20060102150405") + ".txt"
			req, _ := http.NewRequest("PUT", testObj, strings.NewReader("test"))
			writeResp, err := s.Client.Do(req)
			if err == nil {
				writeResp.Body.Close()
				if writeResp.StatusCode == 200 || writeResp.StatusCode == 201 {
					bucket.Writable = true
				}
			}
		}

		return bucket
	}

	return S3Bucket{}
}

func (s *Scanner) scanAzureBlob(bucketNames []string) {
	fmt.Printf("\n%s[*] Scanning Azure Blob Storage...%s\n", ColorCyan, ColorReset)

	var wg sync.WaitGroup
	results := make(chan S3Bucket, len(bucketNames))
	semaphore := make(chan struct{}, 20)

	for _, bucketName := range bucketNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			bucket := s.checkAzureBlob(name)
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

		if bucket.Takeover {
			vuln := Vulnerability{
				Type:        "Azure Blob Storage Takeover",
				Severity:    "CRITICAL",
				URL:         fmt.Sprintf("https://%s.blob.core.windows.net", bucket.Name),
				Evidence:    "Storage account does not exist but DNS/CNAME points to it - can be claimed!",
				Tool:        "azure-scanner",
				Timestamp:   time.Now(),
				Remediation: "Remove DNS/CNAME record or create the storage account immediately",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] CRITICAL: Azure Blob Takeover possible: %s.blob.core.windows.net%s\n",
				ColorRed, bucket.Name, ColorReset)
		} else if bucket.Public || bucket.Listable {
			vuln := Vulnerability{
				Type:        "Exposed Azure Blob Storage",
				Severity:    "HIGH",
				URL:         fmt.Sprintf("https://%s.blob.core.windows.net", bucket.Name),
				Evidence:    fmt.Sprintf("Public: %v, Listable: %v", bucket.Public, bucket.Listable),
				Tool:        "azure-scanner",
				Timestamp:   time.Now(),
				Remediation: "Disable public access on storage account",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] Azure Blob exposed: %s (Public: %v, Listable: %v)%s\n",
				ColorYellow, bucket.Name, bucket.Public, bucket.Listable, ColorReset)
		} else {
			fmt.Printf("%s[*] Azure Blob found (private): %s%s\n", ColorCyan, bucket.Name, ColorReset)
		}
	}
}

func (s *Scanner) checkAzureBlob(accountName string) S3Bucket {
	bucket := S3Bucket{
		Name:       accountName,
		BucketType: "azure",
	}

	url := fmt.Sprintf("https://%s.blob.core.windows.net", accountName)

	resp, err := s.Client.Get(url)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			testURL := fmt.Sprintf("https://%s.%s", accountName, s.Domain)
			testResp, testErr := s.Client.Get(testURL)
			if testErr == nil {
				testResp.Body.Close()
				bucket.Takeover = true
				bucket.Name = accountName
				return bucket
			}
		}
		return S3Bucket{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "ResourceNotFound") ||
			strings.Contains(bodyStr, "The specified account does not exist") {

			testURL := fmt.Sprintf("http://%s.%s", accountName, s.Domain)
			testResp, err := s.Client.Get(testURL)
			if err == nil {
				testResp.Body.Close()
				bucket.Takeover = true
				bucket.Name = accountName
				return bucket
			}
		}
		return S3Bucket{}
	}

	bucket.Name = accountName

	if resp.StatusCode == 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "<EnumerationResults>") ||
			strings.Contains(bodyStr, "<Containers>") {
			bucket.Public = true
			bucket.Listable = true
		}
	}

	containerURL := url + "/$root"
	containerResp, err := s.Client.Get(containerURL)
	if err == nil {
		defer containerResp.Body.Close()
		if containerResp.StatusCode == 200 {
			bucket.Public = true
		}
	}

	return bucket
}

func (s *Scanner) scanGCPStorage(bucketNames []string) {
	fmt.Printf("\n%s[*] Scanning GCP Cloud Storage...%s\n", ColorCyan, ColorReset)

	var wg sync.WaitGroup
	results := make(chan S3Bucket, len(bucketNames))
	semaphore := make(chan struct{}, 20)

	for _, bucketName := range bucketNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			bucket := s.checkGCPBucket(name)
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
				Type:        "Exposed GCP Cloud Storage",
				Severity:    "HIGH",
				URL:         fmt.Sprintf("https://storage.googleapis.com/%s", bucket.Name),
				Evidence:    fmt.Sprintf("Public: %v, Listable: %v", bucket.Public, bucket.Listable),
				Tool:        "gcp-scanner",
				Timestamp:   time.Now(),
				Remediation: "Remove allUsers permission from bucket",
			}
			s.addVulnerability(vuln)
			fmt.Printf("%s[!] GCP Storage exposed: %s (Public: %v, Listable: %v)%s\n",
				ColorYellow, bucket.Name, bucket.Public, bucket.Listable, ColorReset)
		}
	}
}

func (s *Scanner) checkGCPBucket(bucketName string) S3Bucket {
	bucket := S3Bucket{
		Name:       bucketName,
		BucketType: "gcp",
	}

	url := fmt.Sprintf("https://storage.googleapis.com/%s", bucketName)

	resp, err := s.Client.Get(url)
	if err != nil {
		return S3Bucket{}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return S3Bucket{}
	}

	bucket.Name = bucketName

	if resp.StatusCode == 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "<ListBucketResult>") {
			bucket.Public = true
			bucket.Listable = true
		}
	}

	return bucket
}

func (s *Scanner) generateBucketNames() []string {
	domain := strings.ReplaceAll(s.Domain, ".", "-")
	domainParts := strings.Split(s.Domain, ".")
	companyName := domainParts[0]

	baseNames := []string{
		s.Domain,
		domain,
		companyName,
		strings.ReplaceAll(s.Domain, ".", ""),
		strings.ToLower(s.Domain),
		strings.ToUpper(companyName),
	}

	suffixes := []string{
		"", "-backup", "-backups", "-bak", "-bkp",
		"-prod", "-production", "-prd",
		"-dev", "-development", "-devel",
		"-test", "-testing", "-tst",
		"-stage", "-staging", "-stg",
		"-assets", "-static", "-files", "-uploads", "-media",
		"-data", "-database", "-db",
		"-logs", "-log",
		"-images", "-img", "-pics", "-photos",
		"-documents", "-docs",
		"-archive", "-archives",
		"-www", "-web", "-site",
		"-app", "-application",
		"-api", "-rest",
		"-public", "-private", "-internal",
		"-old", "-new", "-v2", "-v3",
		"-tmp", "-temp", "-temporary",
		"-storage", "-store",
		"-admin", "-administrator",
		"-user", "-users", "-customer", "-customers",
		"-content", "-contents",
		"-videos", "-video",
		"-downloads", "-download",
		"-resources", "-resource",
		"-frontend", "-backend",
		"-mobile", "-ios", "-android",
		"-cdn", "-cloudfront",
	}

	prefixes := []string{
		"", "prod-", "dev-", "test-", "staging-",
		"backup-", "old-", "new-", "temp-",
		"my-", "company-", "app-",
	}

	var buckets []string
	seen := make(map[string]bool)

	for _, base := range baseNames {
		for _, prefix := range prefixes {
			for _, suffix := range suffixes {
				name := prefix + base + suffix
				if !seen[name] && len(name) >= 3 && len(name) <= 63 {
					seen[name] = true
					buckets = append(buckets, strings.ToLower(name))
				}
			}
		}
	}

	for _, sub := range s.Result.Subdomains {
		subParts := strings.Split(sub, ".")
		if len(subParts) > 0 {
			subName := strings.ReplaceAll(subParts[0], ".", "-")
			if !seen[subName] && len(subName) >= 3 {
				seen[subName] = true
				buckets = append(buckets, strings.ToLower(subName))
			}

			combined := companyName + "-" + subName
			if !seen[combined] && len(combined) <= 63 {
				seen[combined] = true
				buckets = append(buckets, strings.ToLower(combined))
			}
		}
	}

	return buckets
}

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

	fmt.Printf("%s[✓] Analyzed %d JS files, found %d crypto issues%s\n",
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
					} else {
						jsURL = host + "/" + jsURL
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
		"AES Encryption": {
			regex:       `(?i)(?:CryptoJS\.)?AES\.(?:encrypt|decrypt)`,
			severity:    "INFO",
			findingType: "AES Implementation Found",
		},
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
		"Private Keys": {
			regex:       `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`,
			severity:    "CRITICAL",
			findingType: "Private Key Exposed",
		},
		"JWT Secret": {
			regex:       `(?i)jwt[_-]?secret\s*[:=]\s*["'][^"']+["']`,
			severity:    "CRITICAL",
			findingType: "JWT Secret Exposed",
		},
		"Weak Crypto MD5/SHA1": {
			regex:       `(?i)(?:MD5|SHA1|DES|RC4)\(`,
			severity:    "MEDIUM",
			findingType: "Weak Cryptography",
		},
		"Math.random": {
			regex:       `Math\.random\(\)`,
			severity:    "LOW",
			findingType: "Weak Random Number Generator",
		},
		"Crypto Library": {
			regex:       `(?i)crypto-js|sjcl|forge|jsencrypt`,
			severity:    "INFO",
			findingType: "Crypto Library Detected",
		},
		"UTF8 Encoding Issues": {
			regex:       `(?i)utf8|UTF-8|btoa|atob|encodeURI|decodeURI`,
			severity:    "INFO",
			findingType: "UTF-8/Base64 Encoding Usage",
		},
		"Potential XSS Sink": {
			regex:       `(?i)\.innerHTML\s*=|document\.write\(|eval\(`,
			severity:    "HIGH",
			findingType: "Potential XSS Sink",
		},
		"Database Connection": {
			regex:       `(?i)(?:mysql|postgres|mongodb|redis)://[^"'\s]+`,
			severity:    "CRITICAL",
			findingType: "Database Connection String",
		},
		"OAuth Tokens": {
			regex:       `(?i)(?:oauth|bearer)[_-]?token["']?\s*[:=]\s*["'][a-zA-Z0-9\-_\.]{20,}["']`,
			severity:    "CRITICAL",
			findingType: "OAuth/Bearer Token",
		},
		"GitHub Token": {
			regex:       `ghp_[a-zA-Z0-9]{36}`,
			severity:    "CRITICAL",
			findingType: "GitHub Personal Access Token",
		},
		"Slack Token": {
			regex:       `xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}`,
			severity:    "CRITICAL",
			findingType: "Slack Token",
		},
		"Stripe Key": {
			regex:       `(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}`,
			severity:    "CRITICAL",
			findingType: "Stripe API Key",
		},
		"SendGrid Key": {
			regex:       `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`,
			severity:    "CRITICAL",
			findingType: "SendGrid API Key",
		},
		"Twilio Key": {
			regex:       `SK[a-z0-9]{32}`,
			severity:    "CRITICAL",
			findingType: "Twilio API Key",
		},
		"Mailgun API Key": {
			regex:       `key-[a-zA-Z0-9]{32}`,
			severity:    "CRITICAL",
			findingType: "Mailgun API Key",
		},
		"PayPal Token": {
			regex:       `access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}`,
			severity:    "CRITICAL",
			findingType: "PayPal Access Token",
		},
		"Square Token": {
			regex:       `sq0atp-[0-9A-Za-z\-_]{22}`,
			severity:    "CRITICAL",
			findingType: "Square Access Token",
		},
		"AWS Secret Key": {
			regex:       `(?i)aws_secret_access_key["']?\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']`,
			severity:    "CRITICAL",
			findingType: "AWS Secret Access Key",
		},
		"Shopify Token": {
			regex:       `shpat_[a-fA-F0-9]{32}`,
			severity:    "CRITICAL",
			findingType: "Shopify Access Token",
		},
		"Mailchimp API Key": {
			regex:       `[a-f0-9]{32}-us[0-9]{1,2}`,
			severity:    "CRITICAL",
			findingType: "Mailchimp API Key",
		},
		"Firebase Key": {
			regex:       `(?i)firebase[_-]?api[_-]?key["']?\s*[:=]\s*["'][A-Za-z0-9_-]{39}["']`,
			severity:    "CRITICAL",
			findingType: "Firebase API Key",
		},
		"NPM Token": {
			regex:       `npm_[A-Za-z0-9]{36}`,
			severity:    "CRITICAL",
			findingType: "NPM Access Token",
		},
		"Docker Hub Token": {
			regex:       `dckr_pat_[a-zA-Z0-9_-]{40,}`,
			severity:    "CRITICAL",
			findingType: "Docker Hub Access Token",
		},
		"GitLab Token": {
			regex:       `glpat-[a-zA-Z0-9_-]{20}`,
			severity:    "CRITICAL",
			findingType: "GitLab Personal Access Token",
		},
	}

	lines := strings.Split(content, "\n")
	foundAnyIssue := false

	for patternName, patternData := range patterns {
		re := regexp.MustCompile(patternData.regex)

		for lineNum, line := range lines {
			if matches := re.FindAllString(line, -1); len(matches) > 0 {
				for _, match := range matches {
					foundAnyIssue = true

					contextStart := lineNum - 3
					if contextStart < 0 {
						contextStart = 0
					}
					contextEnd := lineNum + 4
					if contextEnd > len(lines) {
						contextEnd = len(lines)
					}

					context := strings.Join(lines[contextStart:contextEnd], "\n")

					displayMatch := match
					if patternData.severity == "CRITICAL" && len(match) > 30 {
						displayMatch = match[:15] + "...[REDACTED]..." + match[len(match)-10:]
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

					if patternData.severity == "CRITICAL" || patternData.severity == "HIGH" {
						fmt.Printf("\n%s+============================================================+%s\n", ColorRed, ColorReset)
						fmt.Printf("%s| %s: %s%s\n", ColorRed, patternData.severity, patternName, ColorReset)
						fmt.Printf("%s+============================================================+%s\n", ColorRed, ColorReset)
						fmt.Printf("%sFile:%s %s\n", ColorCyan, ColorReset, filepath.Base(url))
						fmt.Printf("%sLine:%s %d\n", ColorCyan, ColorReset, lineNum+1)
						fmt.Printf("%sType:%s %s\n", ColorCyan, ColorReset, patternData.findingType)
						fmt.Printf("%sMatch:%s %s\n\n", ColorYellow, ColorReset, displayMatch)

						fmt.Printf("%sContext:%s\n", ColorCyan, ColorReset)
						fmt.Printf("%s+-----------------------------------------------------------+%s\n", ColorBlue, ColorReset)
						for i, ctxLine := range strings.Split(context, "\n") {
							currentLine := contextStart + i + 1
							if currentLine == lineNum+1 {
								fmt.Printf("%s| %s%4d | %s%s%s\n", ColorBlue, ColorRed, currentLine, ColorReset, ctxLine, ColorReset)
							} else {
								fmt.Printf("%s| %s%4d | %s\n", ColorBlue, ColorWhite, currentLine, ctxLine, ColorReset)
							}
						}
						fmt.Printf("%s+-----------------------------------------------------------+%s\n", ColorBlue, ColorReset)
						fmt.Printf("%sFull URL:%s %s\n", ColorCyan, ColorReset, url)
						fmt.Println()

						vuln := Vulnerability{
							Type:        fmt.Sprintf("JS Crypto: %s", patternData.findingType),
							Severity:    patternData.severity,
							URL:         url,
							Evidence:    fmt.Sprintf("Line %d: %s", lineNum+1, displayMatch),
							Tool:        "js-analyzer",
							Timestamp:   time.Now(),
							Remediation: "Remove hardcoded secrets and use environment variables",
						}
						s.addVulnerability(vuln)
					} else if patternData.severity == "MEDIUM" {
						fmt.Printf("%s[!] %s: %s in %s (line %d)%s\n",
							ColorYellow, patternData.findingType, displayMatch, filepath.Base(url), lineNum+1, ColorReset)
					} else {
						fmt.Printf("%s[*] %s detected in %s (line %d)%s\n",
							ColorCyan, patternData.findingType, filepath.Base(url), lineNum+1, ColorReset)
					}
				}
			}
		}
	}

	if foundAnyIssue {
		fmt.Printf("\n%s%s%s\n\n", ColorBold, strings.Repeat("-", 70), ColorReset)
	}
}

func (s *Scanner) runNuclei() {
	fmt.Printf("\n%s%s[+] MODULE: NUCLEI SCAN%s\n", ColorBold, ColorBlue, ColorReset)

	hostsFile, err := os.Create("live_hosts.txt")
	if err != nil {
		fmt.Printf("%s[!] Error creating live_hosts.txt: %v%s\n", ColorRed, err, ColorReset)
		return
	}

	if len(s.Result.LiveHosts) == 0 {
		fmt.Printf("%s[!] No live hosts to scan%s\n", ColorYellow, ColorReset)
		return
	}

	for _, host := range s.Result.LiveHosts {
		fmt.Fprintln(hostsFile, host)
	}
	hostsFile.Close()

	fmt.Printf("%s[*] Created live_hosts.txt with %d hosts%s\n", ColorCyan, len(s.Result.LiveHosts), ColorReset)

	nucleiPath := ""
	possiblePaths := []string{
		"nuclei",
		"/usr/local/bin/nuclei",
		"/usr/bin/nuclei",
		filepath.Join(os.Getenv("HOME"), "go", "bin", "nuclei"),
		filepath.Join(os.Getenv("GOPATH"), "bin", "nuclei"),
	}

	fmt.Printf("%s[*] Searching for nuclei binary...%s\n", ColorCyan, ColorReset)
	for _, path := range possiblePaths {
		fullPath, err := exec.LookPath(path)
		if err == nil {
			nucleiPath = fullPath
			fmt.Printf("%s[✓] Found nuclei at: %s%s\n", ColorGreen, fullPath, ColorReset)
			break
		}
	}

	if nucleiPath == "" {
		fmt.Printf("%s[!] Nuclei not found in any of these locations:%s\n", ColorRed, ColorReset)
		for _, path := range possiblePaths {
			fmt.Printf("%s    - %s%s\n", ColorYellow, path, ColorReset)
		}
		fmt.Printf("%s[*] Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest%s\n", ColorYellow, ColorReset)
		fmt.Printf("%s[*] Then run: export PATH=$PATH:~/go/bin%s\n", ColorYellow, ColorReset)
		return
	}

	templatesPath := filepath.Join(os.Getenv("HOME"), "nuclei-templates")
	if _, err := os.Stat(templatesPath); os.IsNotExist(err) {
		fmt.Printf("%s[!] Nuclei templates not found, updating...%s\n", ColorYellow, ColorReset)
		updateCmd := exec.Command(nucleiPath, "-update-templates")
		updateOutput, err := updateCmd.CombinedOutput()
		if err != nil {
			fmt.Printf("%s[!] Failed to update templates: %v%s\n", ColorRed, err, ColorReset)
			fmt.Printf("%s%s%s\n", ColorYellow, string(updateOutput), ColorReset)
		} else {
			fmt.Printf("%s[✓] Templates updated successfully%s\n", ColorGreen, ColorReset)
		}
	}

	fmt.Printf("%s[*] Starting nuclei scan (this may take a few minutes)...%s\n", ColorCyan, ColorReset)

	cmd := exec.Command(nucleiPath,
		"-list", "live_hosts.txt",
		"-severity", "critical,high,medium",
		"-json",
		"-silent",
		"-rate-limit", "150",
		"-concurrency", "50",
		"-timeout", "10",
		"-retries", "1",
		"-no-interactsh",
	)

	cmd.Env = append(os.Environ(), "HOME="+os.Getenv("HOME"))

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	output := stdout.String()
	errorOutput := stderr.String()

	if err != nil {
		fmt.Printf("%s[!] Nuclei execution error: %v%s\n", ColorRed, err, ColorReset)
		if errorOutput != "" {
			fmt.Printf("%s[!] Stderr: %s%s\n", ColorYellow, errorOutput, ColorReset)
		}

		if output == "" {
			return
		}
	}

	if output == "" {
		fmt.Printf("%s[*] No vulnerabilities found by Nuclei%s\n", ColorCyan, ColorReset)
		return
	}

	vulnerabilitiesFound := 0
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		var result map[string]interface{}

		if err := json.Unmarshal([]byte(line), &result); err == nil {
			vulnerabilitiesFound++

			severity := "MEDIUM"
			if info, ok := result["info"].(map[string]interface{}); ok {
				if sev, ok := info["severity"].(string); ok {
					severity = strings.ToUpper(sev)
				}
			}

			templateID := "unknown"
			if tid, ok := result["template-id"].(string); ok {
				templateID = tid
			}

			host := "unknown"
			if h, ok := result["host"].(string); ok {
				host = h
			}

			matchedAt := ""
			if ma, ok := result["matched-at"].(string); ok {
				matchedAt = ma
			}

			vuln := Vulnerability{
				Type:      fmt.Sprintf("Nuclei: %s", templateID),
				Severity:  severity,
				URL:       host,
				Evidence:  matchedAt,
				Tool:      "nuclei",
				Timestamp: time.Now(),
			}

			s.addVulnerability(vuln)

			color := ColorYellow
			if severity == "CRITICAL" {
				color = ColorRed
			} else if severity == "HIGH" {
				color = ColorRed
			}

			fmt.Printf("%s[!] %s: %s on %s%s\n", color, severity, templateID, host, ColorReset)
		}
	}

	if vulnerabilitiesFound > 0 {
		fmt.Printf("\n%s[✓] Nuclei found %d vulnerabilities%s\n", ColorGreen, vulnerabilitiesFound, ColorReset)
	} else {
		fmt.Printf("%s[*] Nuclei scan completed - no vulnerabilities found%s\n", ColorCyan, ColorReset)
	}
}

func (s *Scanner) scanPorts() {
	fmt.Printf("\n%s%s[+] MODULE: PORT SCANNING%s\n", ColorBold, ColorBlue, ColorReset)

	var domains []string
	seen := make(map[string]bool)

	for _, host := range s.Result.LiveHosts {
		domain := strings.TrimPrefix(host, "https://")
		domain = strings.TrimPrefix(domain, "http://")
		domain = strings.Split(domain, "/")[0]
		domain = strings.Split(domain, ":")[0]

		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}

	domainsFile, _ := os.Create("domains.txt")
	for _, domain := range domains {
		fmt.Fprintln(domainsFile, domain)
	}
	domainsFile.Close()

	cmd := exec.Command("naabu",
		"-l", "domains.txt",
		"-top-ports", "100",
		"-silent",
		"-json",
	)

	output, err := cmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		var result map[string]interface{}

		if err := json.Unmarshal([]byte(line), &result); err == nil {
			port := result["port"]
			host := result["host"]

			interestingPorts := map[int]string{
				21:    "FTP",
				22:    "SSH",
				23:    "Telnet",
				3306:  "MySQL",
				5432:  "PostgreSQL",
				27017: "MongoDB",
				6379:  "Redis",
				9200:  "Elasticsearch",
				8080:  "HTTP-Alt",
				8443:  "HTTPS-Alt",
			}

			if portNum, ok := port.(float64); ok {
				if service, found := interestingPorts[int(portNum)]; found {
					fmt.Printf("%s[*] Found %s on %v:%v%s\n",
						ColorCyan, service, host, int(portNum), ColorReset)
				}
			}
		}
	}
}

func (s *Scanner) fuzzDirectories() {
	fmt.Printf("\n%s%s[+] MODULE: DIRECTORY FUZZING%s\n", ColorBold, ColorBlue, ColorReset)

	sensitivePaths := []string{
		"/.git/HEAD",
		"/.env",
		"/.aws/credentials",
		"/admin",
		"/api/v1",
		"/graphql",
		"/backup",
		"/.DS_Store",
		"/config",
		"/swagger.json",
		"/api-docs",
		"/.gitlab-ci.yml",
		"/composer.json",
		"/package.json",
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

					if len(body) > 0 && !strings.Contains(string(body), "404") {
						vuln := Vulnerability{
							Type:        "Information Disclosure",
							Severity:    "MEDIUM",
							URL:         testURL,
							Evidence:    fmt.Sprintf("Sensitive file exposed (Status: %d)", resp.StatusCode),
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
	fmt.Printf("\n%s%s[+] MODULE: CORS MISCONFIGURATION%s\n", ColorBold, ColorBlue, ColorReset)

	evilOrigins := []string{
		"https://evil.com",
		"null",
		"https://attacker.com",
	}

	for _, host := range s.Result.LiveHosts {
		for _, origin := range evilOrigins {
			req, _ := http.NewRequest("GET", host, nil)
			req.Header.Set("Origin", origin)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := s.Client.Do(req)
			if err != nil {
				continue
			}

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := resp.Header.Get("Access-Control-Allow-Credentials")
			resp.Body.Close()

			if acao == origin || acao == "*" {
				if acac == "true" || acao == origin {
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
					break
				}
			}
		}
	}
}

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
package main

import (
	"bufio"
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
	Domain   string
	Output   string
	Threads  int
	Modules  []string
	Result   *ScanResult
	mu       sync.Mutex
	Client   *http.Client
}

func main() {
	banner()

	domain := flag.String("d", "", "Target domain (required)")
	modules := flag.String("m", "s,sqli,xss,ssrf,aes,nuclei", "Modules: s(subdomain),sqli,xss,ssrf,aes(jscrypto),nuclei,s3")
	output := flag.String("o", "scan_results.json", "Output file")
	threads := flag.Int("t", 50, "Number of threads")
	flag.Parse()

	if *domain == "" {
		fmt.Println(ColorRed + "[!] Domain is required. Use -d flag" + ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	scanner := &Scanner{
		Domain:  *domain,
		Output:  *output,
		Threads: *threads,
		Modules: strings.Split(*modules, ","),
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
	fmt.Printf("%s[*] Modules: %s%s\n", ColorCyan, *modules, ColorReset)
	fmt.Printf("%s[*] Threads: %d%s\n\n", ColorCyan, *threads, ColorReset)

	scanner.Run()
}

func banner() {
	fmt.Printf("%s%s", ColorCyan, `
+=================================================================+
|         *UCK* SCANNER v4.0 - GO EDITION                        |
|       High-Quality Vulnerability Hunter                        |
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

func (s *Scanner) mineParameters() {
	fmt.Printf("\n%s%s[+] MODULE: PARAMETER MINING%s\n", ColorBold, ColorBlue, ColorReset)
	fmt.Printf("%s[*] Mining parameters from all live hosts...%s\n", ColorCyan, ColorReset)

	var wg sync.WaitGroup
	paramChan := make(chan Parameter, 1000)

	// Method 0: Katana deep crawling (if available)
	fmt.Printf("%s[*] Method 0: Katana deep crawling...%s\n", ColorCyan, ColorReset)
	katanaParams := s.runKatana()
	for _, param := range katanaParams {
		paramChan <- param
	}

	// Method 1: Custom extraction from HTML/JS
	fmt.Printf("%s[*] Method 1: Custom HTML/JS parameter extraction...%s\n", ColorCyan, ColorReset)
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

	go func() {
		wg.Wait()
		close(paramChan)
	}()

	seen := make(map[string]bool)
	for param := range paramChan {
		key := fmt.Sprintf("%s_%s_%s", param.URL, param.Method, param.ParamName)
		if !seen[key] {
			seen[key] = true
			s.mu.Lock()
			s.Result.Parameters = append(s.Result.Parameters, param)
			s.mu.Unlock()
		}
	}

	fmt.Printf("%s[✓] Custom extraction found %d parameters%s\n", ColorGreen, len(s.Result.Parameters), ColorReset)

	// Method 2: Use paramspider if available
	fmt.Printf("%s[*] Method 2: Running paramspider...%s\n", ColorCyan, ColorReset)
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

	// Method 3: Use gau (GetAllURLs) for archived parameters
	fmt.Printf("%s[*] Method 3: Running gau for archived URLs...%s\n", ColorCyan, ColorReset)
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

	fmt.Printf("%s[✓] Total mined %d unique parameters%s\n", ColorGreen, len(s.Result.Parameters), ColorReset)

	// Save parameters to file
	s.saveParametersToFile()

	// Method 4: Fuzz for hidden parameters using common wordlist
	fmt.Printf("%s[*] Method 4: Fuzzing for hidden parameters...%s\n", ColorCyan, ColorReset)
	s.fuzzHiddenParameters()
}

func (s *Scanner) runKatana() []Parameter {
	var params []Parameter

	// Check if katana is installed
	if _, err := exec.LookPath("katana"); err != nil {
		fmt.Printf("%s[!] Katana not found, skipping deep crawling%s\n", ColorYellow, ColorReset)
		fmt.Printf("%s[*] Install: go install github.com/projectdiscovery/katana/cmd/katana@latest%s\n", ColorYellow, ColorReset)
		return params
	}

	// Save live hosts for katana
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

	fmt.Printf("%s[✓] Katana crawled %d URLs and found %d parameters%s\n", 
		ColorGreen, crawledURLs, len(params), ColorReset)

	return params
}

func (s *Scanner) runParamSpider() []Parameter {
	var params []Parameter

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

	return params
}

func (s *Scanner) runGau() []Parameter {
	var params []Parameter

	cmd := exec.Command("gau", s.Domain, "--threads", "10", "--blacklist", "png,jpg,gif,css,woff")
	output, err := cmd.Output()
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
						paramName := strings.ToLower(strings.TrimSpace(kv[0]))

						skipParams := map[string]bool{
							"family": true, "display": true, "subset": true, "utm_source": true,
							"utm_medium": true, "utm_campaign": true, "fbclid": true, "gclid": true,
						}

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

	fmt.Printf("%s[✓] gau found %d archived parameters%s\n", ColorGreen, len(params), ColorReset)
	return params
}

func (s *Scanner) fuzzHiddenParameters() {
	commonParams := []string{
		"id", "user", "account", "number", "order", "no", "doc", "key", "email", "group", "profile",
		"edit", "report", "file", "document", "folder", "path", "url", "redirect", "return", "view",
		"preview", "download", "callback", "data", "q", "search", "query", "keyword", "filter",
		"category", "type", "sort", "order", "lang", "page", "offset", "limit", "start", "end",
	}

	fmt.Printf("%s[*] Testing %d common parameter names on live hosts...%s\n", ColorCyan, len(commonParams), ColorReset)

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
			fmt.Printf("%s[✓] Found hidden param: %s on %s%s\n", ColorGreen, param.ParamName, param.URL, ColorReset)
		}
	}

	if fuzzCount > 0 {
		fmt.Printf("%s[✓] Parameter fuzzing found %d hidden parameters%s\n", ColorGreen, fuzzCount, ColorReset)
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

	urlRegex := regexp.MustCompile(`(?:href|src|action)=["']([^"']+\?[^"']+)["']`)
	matches := urlRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, match := range matches {
		if len(match) > 1 {
			fullURL := match[1]

			if strings.Contains(fullURL, "google") ||
				strings.Contains(fullURL, "fonts.") ||
				strings.Contains(fullURL, "cdn.") ||
				strings.Contains(fullURL, "facebook") ||
				strings.Contains(fullURL, "twitter") {
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

							if skipParams[paramName] {
								continue
							}

							if len(paramName) < 2 || regexp.MustCompile(`^\d+$`).MatchString(paramName) {
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

	formRegex := regexp.MustCompile(`<form[^>]*action=["']([^"']*)["'][^>]*>([\s\S]*?)</form>`)
	formMatches := formRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, formMatch := range formMatches {
		if len(formMatch) > 2 {
			action := formMatch[1]
			formBody := formMatch[2]

			if strings.Contains(action, "google") ||
				strings.Contains(action, "facebook") ||
				strings.Contains(action, "twitter") {
				continue
			}

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

					if skipParams[paramName] ||
						paramName == "csrf" ||
						paramName == "token" ||
						strings.Contains(paramName, "csrf") {
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

	jsAPIRegex := regexp.MustCompile(`(?:fetch|axios|XMLHttpRequest|\.get|\.post)[^(]*\([^)]*["']([^"']+\?[^"']+)["']`)
	jsMatches := jsAPIRegex.FindAllStringSubmatch(bodyStr, -1)

	for _, jsMatch := range jsMatches {
		if len(jsMatch) > 1 {
			apiURL := jsMatch[1]

			if strings.Contains(apiURL, "google") ||
				strings.Contains(apiURL, "cdn.") {
				continue
			}

			if strings.Contains(apiURL, "?") {
				parts := strings.Split(apiURL, "?")
				if len(parts) == 2 {
					paramPairs := strings.Split(parts[1], "&")
					for _, pair := range paramPairs {
						kv := strings.Split(pair, "=")
						if len(kv) >= 1 {
							paramName := strings.ToLower(strings.TrimSpace(kv[0]))

							if skipParams[paramName] {
								continue
							}

							param := Parameter{
								URL:       url,
								Method:    "GET",
								ParamName: paramName,
								ParamType: "API",
							}

							if highValueParams[paramName] {
								param.ParamType = "API_HIGH_VALUE"
							}

							params = append(params, param)
						}
					}
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

func (s *Scanner) scanXSS() {
	fmt.Printf("\n%s%s[+] MODULE: XSS SCANNING (DALFOX)%s\n", ColorBold, ColorBlue, ColorReset)

	if len(s.Result.Parameters) == 0 {
		fmt.Printf("%s[!] No parameters found to test%s\n", ColorYellow, ColorReset)
		return
	}

	fmt.Printf("%s[*] Testing %d parameters with Dalfox...%s\n", ColorCyan, len(s.Result.Parameters), ColorReset)

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

	// Test high-value first
	allParams := append(highValueParams, normalParams...)

	// Limit to reasonable number for speed
	maxTest := 100
	if len(allParams) < maxTest {
		maxTest = len(allParams)
	}

	testParams := allParams[:maxTest]

	// Save to file for dalfox
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
		fmt.Printf("%s[!] Dalfox error (may not be installed): %v%s\n", ColorYellow, err, ColorReset)
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

	if vulnerabilitiesFound > 0 {
		fmt.Printf("%s[✓] Dalfox found %d XSS vulnerabilities%s\n", ColorGreen, vulnerabilitiesFound, ColorReset)
	} else {
		fmt.Printf("%s[*] No XSS vulnerabilities found%s\n", ColorCyan, ColorReset)
	}
}

func (s *Scanner) scanSQLi() {
	fmt.Printf("\n%s%s[+] MODULE: SQL INJECTION (SQLMAP)%s\n", ColorBold, ColorBlue, ColorReset)

	if len(s.Result.Parameters) == 0 {
		fmt.Printf("%s[!] No parameters found to test%s\n", ColorYellow, ColorReset)
		return
	}

	// Prioritize HIGH_VALUE parameters for SQLi
	highValueParams := []Parameter{}
	sqlKeywords := map[string]bool{
		"id": true, "user": true, "userid": true, "account": true, "email": true,

		"order": true, "search": true, "query": true, "filter": true, "page": true,
	}

	for _, param := range s.Result.Parameters {
		if strings.Contains(param.ParamType, "HIGH_VALUE") || sqlKeywords[param.ParamName] {
			highValueParams = append(highValueParams, param)
		}
	}

	fmt.Printf("%s[*] Testing %d high-priority parameters for SQLi...%s\n", ColorCyan, len(highValueParams), ColorReset)

	// Test top 20 high-value parameters
	maxTests := 20
	if len(highValueParams) < maxTests {
		maxTests = len(highValueParams)
	}

	tested := 0
	for i := 0; i < maxTests && i < len(highValueParams); i++ {
		param := highValueParams[i]
		testURL := fmt.Sprintf("%s?%s=1", param.URL, param.ParamName)

		fmt.Printf("%s[*] Testing [%d/%d]: %s (param: %s)%s\n", 
			ColorCyan, i+1, maxTests, param.URL, param.ParamName, ColorReset)

		cmd := exec.Command("sqlmap",
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
		)

		output, _ := cmd.CombinedOutput()
		tested++

		if strings.Contains(string(output), "injectable") || 
		   strings.Contains(string(output), "vulnerable") ||
		   strings.Contains(string(output), "Parameter:") && strings.Contains(string(output), "Type:") {
			
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
		"http://[::1]",
		"http://0.0.0.0",
		"file:///etc/passwd",
		"http://metadata.google.internal/computeMetadata/v1/",
	}

	for _, param := range s.Result.Parameters {
		for _, payload := range ssrfPayloads {
			testURL := fmt.Sprintf("%s?%s=%s", param.URL, param.ParamName, payload)

			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")

			resp, err := s.Client.Do(req)
			if err == nil {
				body, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()

				if strings.Contains(string(body), "ami-id") ||
					strings.Contains(string(body), "instance-id") ||
					strings.Contains(string(body), "root:x:0:0") ||
					strings.Contains(string(body), "Google Cloud") {

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
					fmt.Printf("%s[!] CRITICAL: SSRF found at %s%s\n", ColorRed, param.URL, ColorReset)
					break
				}
			}
		}
	}
}

func (s *Scanner) scanS3
