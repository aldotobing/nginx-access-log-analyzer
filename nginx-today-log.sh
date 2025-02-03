#!/bin/bash

# Path ke file log
LOG_FILE="/var/log/nginx/access.log"
HTML_FILE="/usr/share/nginx/html/nginx_today.html"
TEMP_LOG="/tmp/today_log.txt"

# New paths for security logs
SECURITY_LOGS_DIR="/usr/share/nginx/html/security_logs"
SQL_LOG="$SECURITY_LOGS_DIR/sql_injection.log"
XSS_LOG="$SECURITY_LOGS_DIR/xss.log"
DIR_LOG="$SECURITY_LOGS_DIR/directory_traversal.log"
CMD_LOG="$SECURITY_LOGS_DIR/command_injection.log"


TODAY=$(date +%d/%b/%Y)

sudo awk -v today="$TODAY" '$0 ~ "\\[" today {print $0}' "$LOG_FILE" > "$TEMP_LOG"

# Enhanced security patterns
SQL_INJECTION_PATTERNS=(
    "(%27|'|--|;|-- )"                         # Single quotes, comments, or semicolons
    "(%20|\+)?(SELECT|UNION|INSERT|DELETE|UPDATE|ALTER|DROP|EXEC)(%20|\+)"  # SQL commands
    "OR(%20|\+)(\d|')?='?"                     # OR-based injection
    "AND(%20|\+)(\d|')?='?"                    # AND-based injection
    "(\%27|')\s*--"                            # Single quote with comment, stricter
    "CHAR\([0-9,]+\)"                          # Character encoding
    "CONCAT\("                                 # String concatenation
)


XSS_PATTERNS=(
    # Basic XSS patterns
    "<script[^>]*>"                      # <script> tags, with or without attributes
    "javascript:"                        # javascript: URI scheme
    "onerror\s*="                        # Event handler: onerror
    "onload\s*="                         # Event handler: onload
    "onmouseover\s*="                    # Event handler: onmouseover
    "onclick\s*="                        # Event handler: onclick
    "eval\("                             # Use of eval()
    "alert\("                            # Use of alert()
    "document\.cookie"                   # Accessing document cookies
    "document\.location"                 # Accessing document location
    "fromCharCode\s*\("                  # fromCharCode() usage
    "expression\s*\("                    # CSS expressions (deprecated but potentially dangerous)
    "<img[^>]*src\s*=\s*['\"]?javascript:" # <img> with JavaScript payload
    "<iframe[^>]*>"                      # <iframe> tag
    "<object[^>]*>"                      # <object> tag
    "<embed[^>]*>"                       # <embed> tag
    "<svg[^>]*on[^>]*="                  # SVG elements with event handlers
    "<math[^>]*on[^>]*="                 # MathML elements with event handlers
    "<[^>]+style\s*=\s*['\"]?[^>]*expression\s*\(" # Inline CSS with expressions
    "data:text/html"                     # Data URI for inline HTML
    "vbscript:"                          # VBScript URI scheme
    "innerHTML"                          # Assignment to innerHTML
    "parentNode\.insertBefore"           # DOM manipulation
    "setTimeout\s*\("                    # Use of setTimeout()
    "setInterval\s*\("                   # Use of setInterval()
)


DIR_TRAVERSAL_PATTERNS=(
    "(\.\./){2,}"                               # Multiple ../ for traversal
    "(%2e){2,}"                                 # URL-encoded ..
    "/etc/passwd"                               # Common Linux files
    "wp-config(\.php)?"                          # WordPress config
    "c:/windows"                                # Windows paths
    "file:\s*/"                                 # File URIs
	"(/|%2f)(root|bin|home|usr|opt)/" 
)	

COMMAND_INJECTION_PATTERNS=(
    # Common Shell Commands (dengan batasan lebih ketat)
    "\\b(cat|ls|id|uname|whoami|pwd|rm|touch|wget|curl|scp|rsync|ftp|nc|nmap|ping|traceroute|telnet|ssh)\\b(\\s+|$)"

    # Shell/Script Invocation
    "\\b(sh|bash|zsh|dash|fish|python[23]?|perl|ruby|php|java|node|gcc|g\\+\\+)\\b(\\s+|$)"

    # Command Injection Indicators
    "[;&|]{2,}"                              # Multiple chaining operators
    "\\$\\(.*?\\)"                           # Subshell execution
    "\\s+[2]?[>|&]"                          # Output or error redirection
    "\\s+[<>]"                               # Simple redirection

    # Dangerous PHP/System Functions
    "\\b(exec|system|passthru|shell_exec|popen|eval|assert|proc_open|pcntl_exec|preg_replace\\(.*?e\\))\\b"

    # Avoid Matching `by=` or API-Like Patterns
    "(?<!by=|sort=|customer_id=|limit=|page=)\\b(id|def\\.id)\\b(\\s+|$)"
)


# Function to count security incidents with improved pattern matching
function count_security_incidents() {
    local log_file=$1
    shift
    local patterns=("$@")
    local pattern_regex=$(IFS="|"; echo "${patterns[*]}")

    # Use a single grep invocation with Perl-compatible regex and case-insensitivity
    local count=$(grep -Pi "$pattern_regex" "$log_file" | wc -l)

    echo "$count"
}

# Security metrics using enhanced patterns
SQL_INJECTION_COUNT=$(count_security_incidents "$TEMP_LOG" "${SQL_INJECTION_PATTERNS[@]}")
XSS_COUNT=$(count_security_incidents "$TEMP_LOG" "${XSS_PATTERNS[@]}")
DIR_TRAVERSAL_COUNT=$(count_security_incidents "$TEMP_LOG" "${DIR_TRAVERSAL_PATTERNS[@]}")
COMMAND_INJECTION_COUNT=$(count_security_incidents "$TEMP_LOG" "${COMMAND_INJECTION_PATTERNS[@]}")

# Basic metrics
REQUEST_COUNT=$(wc -l < "$TEMP_LOG")
UNIQUE_IP_COUNT=$(awk '{print $1}' "$TEMP_LOG" | sort -u | wc -l)

# Error metrics with improved counting
ERROR_404_COUNT=$(awk '$9 == "404"' "$TEMP_LOG" | wc -l)
ERROR_403_COUNT=$(awk '$9 == "403"' "$TEMP_LOG" | wc -l)
ERROR_400_COUNT=$(awk '$9 == "400"' "$TEMP_LOG" | wc -l)
ERROR_500_COUNT=$(awk '$9 == "500"' "$TEMP_LOG" | wc -l)


# Improved IP information function with rate limiting and caching
CACHE_DIR="/tmp/ipinfo_cache"
mkdir -p "$CACHE_DIR"

function get_ipinfo_info() {
    local IP_ADDRESS=$1
    local CACHE_FILE="$CACHE_DIR/${IP_ADDRESS}.json"

    # Check cache (24 hour validity)
    if [ -f "$CACHE_FILE" ] && [ $(( $(date +%s) - $(stat -c %Y "$CACHE_FILE") )) -lt 86400 ]; then
        cat "$CACHE_FILE"
    else
        # Rate limiting - sleep 1 second between requests
        sleep 1
        response=$(curl -s -m 5 "https://ipinfo.io/$IP_ADDRESS/json")
        if [ $? -eq 0 ] && [ ! -z "$response" ]; then
            echo "$response" > "$CACHE_FILE"
            echo "$response"
        else
            echo '{"city":"Unknown","country":"Unknown","loc":"Unknown"}'
        fi
    fi
}

# Enhanced suspicious activity detection
function check_ip_suspicious_activity() {
    local IP=$1
    local suspicious_count=0

    # Check for various suspicious patterns
    local value
    value=$(awk -v ip="$IP" '$1 == ip && $9 ~ /^(400|403|404|405|406|444|494|495|496|497)$/' "$TEMP_LOG" | wc -l)
    suspicious_count=$((suspicious_count + value))

    value=$(awk -v ip="$IP" '$1 == ip' "$TEMP_LOG" | grep -iP "$(IFS="|"; echo "${SQL_INJECTION_PATTERNS[*]}")" | wc -l)
    suspicious_count=$((suspicious_count + value))

    value=$(awk -v ip="$IP" '$1 == ip' "$TEMP_LOG" | grep -iP "$(IFS="|"; echo "${XSS_PATTERNS[*]}")" | wc -l)
    suspicious_count=$((suspicious_count + value))

    value=$(awk -v ip="$IP" '$1 == ip' "$TEMP_LOG" | grep -iP "$(IFS="|"; echo "${DIR_TRAVERSAL_PATTERNS[*]}")" | wc -l)
    suspicious_count=$((suspicious_count + value))

    # Additional checks for rapid requests
    local request_rate
    request_rate=$(awk -v ip="$IP" '$1 == ip' "$TEMP_LOG" | wc -l)
    if [ "$request_rate" -gt 100 ]; then
        suspicious_count=$((suspicious_count + request_rate / 100))
    fi

    echo "$suspicious_count"
}

# Generate Top IPs table with enhanced information
TOP_IPS_TABLE=""
# Generate the top IPs list and save it to a variable before using it in the while loop
TOP_IPS=$(awk '{print $1}' "$TEMP_LOG" | sort | uniq -c | sort -nr | head -n 10)

while IFS= read -r line; do
    COUNT=$(echo "$line" | awk '{print $1}')
    IP=$(echo "$line" | awk '{print $2}')
    INFO=$(get_ipinfo_info "$IP" | jq -r '"\(.city), \(.country), \(.loc)"')

    SUSPICIOUS_COUNT=$(check_ip_suspicious_activity "$IP")
    STATUS="Normal"

    if [ "$SUSPICIOUS_COUNT" -gt 0 ]; then
        if [ "$SUSPICIOUS_COUNT" -gt 10 ]; then
            STATUS="<span style='color: var(--danger)'>High Risk ($SUSPICIOUS_COUNT suspicious activities)</span>"
        else
            STATUS="<span style='color: var(--warning)'>Suspicious ($SUSPICIOUS_COUNT suspicious activities)</span>"
        fi
    fi

    TOP_IPS_TABLE+="<tr><td>$COUNT</td><td>$IP</td><td>$INFO</td><td>$STATUS</td></tr>"
done <<< "$TOP_IPS"

# Generate Top URLs table
TOP_URLS_TABLE=""
TOP_URLS=$(awk '{print $7}' "$TEMP_LOG" | sort | uniq -c | sort -nr | head -n 10)

while IFS= read -r line; do
    COUNT=$(echo "$line" | awk '{print $1}')
    URL=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^[ \t]*//')
    STATUS_CODE=$(awk -v url="$URL" '$7 == url {print $9}' "$TEMP_LOG" | head -n 1)
    
    STATUS_COLOR="var(--success)"
    if [ "$STATUS_CODE" = "404" ]; then
        STATUS_COLOR="var(--warning)"
    elif [ "$STATUS_CODE" = "403" ]; then
        STATUS_COLOR="var(--danger)"
    fi
    
    TOP_URLS_TABLE+="<tr><td>$COUNT</td><td>$URL</td><td style='color: $STATUS_COLOR'>$STATUS_CODE</td></tr>"
done <<< "$TOP_URLS"


# Format recent log entries with download button
LOG_ENTRIES=$(cat /tmp/today_log.txt | while IFS= read -r line; do
    echo "<div class='log-entry'>$line</div>"
done)

# Write the complete HTML file
sudo cat > $HTML_FILE << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nginx Log Analysis Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
<style>
:root {
    --primary: #2563eb;
    --secondary: #475569;
    --danger: #dc2626;
    --warning: #f59e0b;
    --success: #16a34a;
    --border-color: #e2e8f0;
    --background: #f8fafc;
    --text-color: #334155;
    --security-accent: #7c3aed;
}

body {
    font-family: system-ui, -apple-system, sans-serif;
    line-height: 1.5;
    margin: 0;
    padding: clamp(10px, 3vw, 20px);
    background: var(--background);
    color: var(--text-color);
    -webkit-font-smoothing: antialiased;
}

.dashboard {
    max-width: min(95vw, 1200px);
    margin: 0 auto;
    width: 100%;
}

.header {
    background: white;
    padding: clamp(15px, 4vw, 20px);
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    margin-bottom: clamp(15px, 4vw, 20px);
    border: 1px solid var(--border-color);
}

.header h1 {
    margin: 0;
    color: var(--primary);
    font-size: clamp(18px, 5vw, 24px);
    line-height: 1.2;
}

.date {
    color: var(--secondary);
    font-size: clamp(12px, 3.5vw, 14px);
    margin-top: 5px;
}

/* Metrics section styles */
.metrics-section {
    background: white;
    padding: clamp(15px, 4vw, 20px);
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    margin-bottom: clamp(15px, 4vw, 20px);
    border: 1px solid var(--border-color);
}

.metrics-section h2 {
    margin: 0 0 15px 0;
    font-size: clamp(16px, 4.5vw, 20px);
    color: var(--primary);
}

.security-section h2 {
    color: var(--security-accent);
}

/* Responsive grid */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr));
    gap: clamp(10px, 2vw, 20px);
}

.metric-card {
    background: white;
    padding: clamp(12px, 3vw, 20px);
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    border: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.security-section .metric-card {
    background: linear-gradient(to bottom right, #fcfaff, white);
    border-color: #ddd6fe;
}

.metric-card h3 {
    margin: 0;
    color: var(--secondary);
    font-size: clamp(14px, 4vw, 18px);
}

.security-section .metric-card h3 {
    color: var(--security-accent);
}

.metric-value {
    font-size: clamp(18px, 5vw, 24px);
    font-weight: bold;
}

/* Table responsive styles */
.section {
    margin-top: clamp(20px, 5vw, 40px);
    overflow-x: auto;
    background: white;
    border-radius: 12px;
    padding: clamp(10px, 3vw, 20px);
    border: 1px solid var(--border-color);
}

.section h2 {
    font-size: clamp(16px, 4.5vw, 20px);
    color: var(--primary);
    margin-top: 0;
    margin-bottom: 15px;
}

/* Make tables scrollable horizontally on mobile */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 0;
    min-width: 500px; /* Ensure minimum width for scrolling */
}

table th, table td {
    padding: clamp(8px, 2vw, 10px);
    text-align: left;
    border-bottom: 1px solid var(--border-color);
    white-space: nowrap;
    font-size: clamp(12px, 3.5vw, 14px);
}

table th {
    background-color: #f1f5f9;
    color: var(--primary);
    position: sticky;
    top: 0;
    z-index: 1;
}

/* Log entries styles */
.log-entries-container {
    max-height: clamp(250px, 60vh, 400px);
    overflow-y: auto;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    background-color: #f9f9f9;
    padding: clamp(8px, 2vw, 12px);
}

.log-entry {
    background: white;
    padding: clamp(8px, 2vw, 12px);
    margin-bottom: 8px;
    border-radius: 8px;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    font-size: clamp(12px, 3.5vw, 14px);
    word-break: break-word;
}

/* Custom scrollbar for better mobile experience */
.log-entries-container::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}

.log-entries-container::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 3px;
}

.log-entries-container::-webkit-scrollbar-thumb {
    background: var(--secondary);
    border-radius: 3px;
}

/* Better touch targets for mobile */
button, select, input {
    min-height: 44px;
    padding: 8px 12px;
}

/* Print styles */
@media print {
    body {
        padding: 0;
        background: white;
    }

    .dashboard {
        max-width: 100%;
    }

    .log-entries-container {
        max-height: none;
        overflow: visible;
    }

    .section {
        break-inside: avoid;
    }
}

/* Modal styles */
.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    z-index: 1000;
}

.modal-content {
    position: relative;
    background-color: white;
    margin: 50px auto;
    padding: 20px;
    width: 90%;
    max-width: 800px;
    max-height: 80vh;
    border-radius: 12px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    padding-bottom: 15px;
    border-bottom: 1px solid var(--border-color);
}

.modal-title {
    margin: 0;
    color: var(--primary);
    font-size: 20px;
}

.modal-close {
    background: none;
    border: none;
    font-size: 24px;
    cursor: pointer;
    color: var(--secondary);
}

.modal-body {
    max-height: calc(80vh - 100px);
    overflow-y: auto;
    padding: 10px 0;
}

.log-line {
    font-family: monospace;
    padding: 8px;
    margin: 4px 0;
    background: #f8fafc;
    border-radius: 4px;
    white-space: pre-wrap;
    word-break: break-all;
}

/* Enhanced card styles */
.security-card {
    cursor: pointer;
    transition: all 0.2s ease;
    position: relative;
    overflow: hidden;
}

.security-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(124, 58, 237, 0.05);
    opacity: 0;
    transition: opacity 0.2s ease;
}

.security-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.security-card:hover::before {
    opacity: 1;
}

.security-card:active {
    transform: translateY(0);
}

/* Enhanced modal styles */
.modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.5);
    z-index: 1000;
    opacity: 0;
    transition: opacity 0.2s ease;
}

.modal.show {
    opacity: 1;
}

.modal-content {
    position: relative;
    background: white;
    margin: 50px auto;
    padding: 20px;
    width: 90%;
    max-width: 800px;
    max-height: 80vh;
    border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
    transform: translateY(-20px);
    transition: transform 0.2s ease;
}

.modal.show .modal-content {
    transform: translateY(0);
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    padding-bottom: 15px;
    border-bottom: 1px solid var(--border-color);
}

.modal-title {
    margin: 0;
    color: var(--security-accent);
    font-size: 20px;
}

.modal-close {
    background: none;
    border: none;
    font-size: 24px;
    cursor: pointer;
    color: var(--secondary);
    padding: 8px;
    border-radius: 4px;
    transition: background 0.2s ease;
}

.modal-close:hover {
    background: rgba(0, 0, 0, 0.05);
}

.modal-body {
    max-height: calc(80vh - 100px);
    overflow-y: auto;
    padding: 10px 0;
}

.log-line {
    font-family: monospace;
    padding: 8px;
    margin: 4px 0;
    background: #f8fafc;
    border-radius: 4px;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 14px;
    line-height: 1.5;
}

.toggle-button {
    background: none;
    border: none;
    cursor: pointer;
    padding: 8px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background-color 0.2s, transform 0.2s;
    color: var(--primary);
}

.toggle-button:hover {
    background-color: rgba(37, 99, 235, 0.1);
}

.toggle-button.active .arrow-icon {
    transform: rotate(180deg);
}

.arrow-icon {
    transition: transform 0.2s;
}

.download-button {
    background-color: var(--primary);
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    transition: background-color 0.2s;
    display: flex;
    align-items: center;
    gap: 8px;
    height: 36px;
}

.download-button:hover {
    background-color: #1d4ed8;
}
</style>

</head>
<body>

<div class="dashboard">
    <div class="header">
        <h1>Nginx Log Analysis Dashboard</h1>
        <div class="date">Date: $TODAY</div>
    </div>

    <div class="metrics-section">
        <h2>General Metrics</h2>
        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Total Requests</h3>
                <div class="metric-value">$REQUEST_COUNT</div>
            </div>
            <div class="metric-card">
                <h3>Unique IPs</h3>
                <div class="metric-value">$UNIQUE_IP_COUNT</div>
            </div>
            <div class="metric-card">
                <h3 class="error-metric">404 Errors</h3>
                <div class="metric-value">$ERROR_404_COUNT</div>
            </div>
            <div class="metric-card">
                <h3 class="error-metric">403 Errors</h3>
                <div class="metric-value">$ERROR_403_COUNT</div>
            </div>
        </div>
    </div>

    <div class="metrics-section security-section">
        <h2>Security Metrics</h2>
        <div class="metrics-grid">
            <div class="metric-card security-card" onclick="showSecurityLogs('sql-modal')" role="button" tabindex="0">
                <h3>SQL Injection Attempts</h3>
                <div class="metric-value">$SQL_INJECTION_COUNT</div>
            </div>
            <div class="metric-card security-card" onclick="showSecurityLogs('dir-modal')" role="button" tabindex="0">
                <h3>Directory Traversal Attempts</h3>
                <div class="metric-value">$DIR_TRAVERSAL_COUNT</div>
            </div>
            <div class="metric-card security-card" onclick="showSecurityLogs('xss-modal')" role="button" tabindex="0">
                <h3>XSS Attempts</h3>
                <div class="metric-value">$XSS_COUNT</div>
            </div>
            <div class="metric-card security-card" onclick="showSecurityLogs('cmd-modal')" role="button" tabindex="0">
                <h3>Command Injection Attempts</h3>
                <div class="metric-value">$COMMAND_INJECTION_COUNT</div>
            </div>
        </div>
    </div>

    <!-- Enhanced modals -->
    <div id="sql-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">SQL Injection Attempts</h3>
                <button class="modal-close" onclick="hideModal('sql-modal')">&times;</button>
            </div>
            <div class="modal-body">
                $(cat "$SQL_LOG" | while IFS= read -r line; do
                    echo "<div class='log-line'>$line</div>"
                done)
            </div>
        </div>
    </div>

    <div id="xss-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">XSS Attempts</h3>
                <button class="modal-close" onclick="hideModal('xss-modal')">&times;</button>
            </div>
            <div class="modal-body">
                $(cat "$XSS_LOG" | while IFS= read -r line; do
                    echo "<div class='log-line'>$line</div>"
                done)
            </div>
        </div>
    </div>

    <div id="dir-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Directory Traversal Attempts</h3>
                <button class="modal-close" onclick="hideModal('dir-modal')">&times;</button>
            </div>
            <div class="modal-body">
                $(cat "$DIR_LOG" | while IFS= read -r line; do
                    echo "<div class='log-line'>$line</div>"
                done)
            </div>
        </div>
    </div>

    <div id="cmd-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Command Injection Attempts</h3>
                <button class="modal-close" onclick="hideModal('cmd-modal')">&times;</button>
            </div>
            <div class="modal-body">
                $(cat "$CMD_LOG" | while IFS= read -r line; do
                    echo "<div class='log-line'>$line</div>"
                done)
            </div>
        </div>
    </div>
    <div class="section">
        <h2>Top 10 IPs with Requests</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>IP Address</th>
                    <th>Location</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                $TOP_IPS_TABLE
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Top 10 Requested URLs</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>URL</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                $TOP_URLS_TABLE
            </tbody>
        </table>
    </div>

    <div class="section">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
        <div style="display: flex; align-items: center; gap: 12px;">
            <h2 style="margin: 0;">Recent Log Entries</h2>
            <button onclick="toggleLogEntries()" class="toggle-button" aria-label="Toggle log entries">
                <svg class="arrow-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M6 9l6 6 6-6"/>
                </svg>
            </button>
        </div>
        <button onclick="downloadLogs()" class="download-button">
            Download Logs
        </button>
    </div>
    <div class="log-entries-container" style="display: none;">
        $LOG_ENTRIES
    </div>
</div>
</div>

<script>
function showSecurityLogs(modalId) {
    const modal = document.getElementById(modalId);
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
    // Add show class after a small delay to trigger animation
    setTimeout(() => {
        modal.classList.add('show');
    }, 10);
}

function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.remove('show');
    setTimeout(() => {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }, 200);
}

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        hideModal(event.target.id);
    }
}

// Close modal on escape key
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(modal => {
            if (modal.style.display === 'block') {
                hideModal(modal.id);
            }
        });
    }
});

// Add keyboard accessibility
document.querySelectorAll('.security-card').forEach(card => {
    card.addEventListener('keypress', function(event) {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            card.click();
        }
    });
});

function downloadLogs() {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(\`$(cat /tmp/today_log.txt)\`));
    element.setAttribute('download', 'today_log.txt');

    element.style.display = 'none';
    document.body.appendChild(element);

    element.click();

    document.body.removeChild(element);
}

function toggleLogEntries() {
    const logContainer = document.querySelector('.log-entries-container');
    const toggleButton = document.querySelector('.toggle-button');
    
    if (logContainer.style.display === 'none') {
        logContainer.style.display = 'block';
        toggleButton.classList.add('active');
    } else {
        logContainer.style.display = 'none';
        toggleButton.classList.remove('active');
    }
}

</script>

</body>
</html>
EOF

echo "Dashboard has been generated at $HTML_FILE"
