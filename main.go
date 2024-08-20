/*
MIT License

Copyright (c) 2024 dgnnj

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	payload "sqli-scanner/payloads"
	"strings"
	"time"
)

// Structure to store SQLi responses
type InjectionResponse struct {
	Vulnerable    bool
	Attack01      string
	MatchString   string
	Vectors       map[string]string
	InjectionType string
	Param         Parameter
	Backend       string
	IsString      bool
}

// Structure to verify basic response
type BasicCheckResponse struct {
	Base               *http.Response
	PossibleDBMS       string
	IsConnectionTested bool
	IsDynamic          bool
	IsResumed          bool
	IsParameterTested  bool
}

// Parameter structure
type Parameter struct {
	Key   string
	Value string
	Type  string
}

// List of random User-Agents
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
}

// Generates a random User-Agent
func getRandomUserAgent() string {
	rand.Seed(time.Now().Unix())
	return userAgents[rand.Intn(len(userAgents))]
}

// General Utility Functions

// Function to send an HTTP request with injection
func injectExpression(urlStr, param, expression string, headers map[string]string) (*http.Response, error) {
	client := &http.Client{}
	fullURL := fmt.Sprintf("%s?%s=%s", urlStr, param, url.QueryEscape(expression))
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return client.Do(req)
}

// Function to send request and measure response time (for Time-based)
func sendTimedRequest(urlStr, paramName, expression string, headers map[string]string) (time.Duration, string, error) {
	start := time.Now()
	resp, err := injectExpression(urlStr, paramName, expression, headers)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	duration := time.Since(start)
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	return duration, bodyString, nil
}

// Basic and Advanced Check Functions

// Basic check function
func basicCheck(urlStr string, headers map[string]string, param Parameter) *BasicCheckResponse {
	isDynamic := false
	var possibleDBMS string

	fmt.Println("Testing connection with the target URL...")
	baseResponse, err := injectExpression(urlStr, param.Key, "", headers)
	if err != nil {
		fmt.Println("Error testing the connection:", err)
		return nil
	}
	defer baseResponse.Body.Close()

	time.Sleep(500 * time.Millisecond)
	secondResponse, err := injectExpression(urlStr, param.Key, "", headers)
	if err != nil {
		fmt.Println("Error testing content stability:", err)
		return nil
	}
	defer secondResponse.Body.Close()

	if baseResponse.ContentLength != secondResponse.ContentLength {
		isDynamic = true
		fmt.Println("The content of the target URL is not stable.")
	} else {
		fmt.Println("The content of the target URL is stable.")
	}

	expressions := []string{"'", "\"", "%27", "%22"}
	for _, expression := range expressions {
		resp, err := injectExpression(urlStr, param.Key, expression, headers)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		bodyString := strings.ToLower(string(bodyBytes))

		if strings.Contains(bodyString, "mysql") {
			possibleDBMS = "MySQL"
			fmt.Printf("Basic heuristic suggests that the parameter '%s' might be injectable (Possible DBMS: %s)\n", param.Key, possibleDBMS)
			break
		}
	}

	if possibleDBMS == "" {
		fmt.Printf("Basic heuristic suggests that the parameter '%s' might not be injectable.\n", param.Key)
	}

	return &BasicCheckResponse{
		Base:               baseResponse,
		PossibleDBMS:       possibleDBMS,
		IsConnectionTested: true,
		IsDynamic:          isDynamic,
		IsResumed:          false,
		IsParameterTested:  false,
	}
}

// Extended DBMS check function
func extendedDBMSCheck(urlStr string, param Parameter, possibleDBMS string, headers map[string]string) string {
	var detectedDBMS string

	fmt.Printf("Testing and confirming the possible DBMS: %s\n", possibleDBMS)
	if possibleDBMS == "MySQL" {
		resp, err := injectExpression(urlStr, param.Key, "SELECT @@version", headers)
		if err == nil && resp != nil {
			defer resp.Body.Close()
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			bodyString := strings.ToLower(string(bodyBytes))

			if strings.Contains(bodyString, "mysql") {
				detectedDBMS = "MySQL"
				fmt.Println("Detected DBMS: MySQL")
			}
		}
	}

	if detectedDBMS == "" {
		fmt.Println("DBMS not detected.")
	} else {
		fmt.Printf("The backend DBMS is %s.\n", detectedDBMS)
	}

	return detectedDBMS
}

// SQLi Detection Functions

// Function to test Boolean-based SQLi
func testBooleanBasedSQLi(urlStr, paramName string, payloads []map[string]string, headers map[string]string, vulnerabilities *[]string) {
	found := false
	for _, payload := range payloads {
		truePayload := payload["true"]
		falsePayload := payload["false"]

		trueResp, err := injectExpression(urlStr, paramName, truePayload, headers)
		if err != nil {
			continue
		}
		defer trueResp.Body.Close()

		falseResp, err := injectExpression(urlStr, paramName, falsePayload, headers)
		if err != nil {
			continue
		}
		defer falseResp.Body.Close()

		if trueResp.ContentLength != falseResp.ContentLength {
			vulnerability := fmt.Sprintf("Boolean-based SQLi detected with payload '%s'", truePayload)
			fmt.Println(vulnerability)
			*vulnerabilities = append(*vulnerabilities, vulnerability)
			found = true
		}
	}

	if !found {
		fmt.Println("No Boolean-based SQLi vulnerabilities detected.")
		*vulnerabilities = append(*vulnerabilities, "No Boolean-based SQLi vulnerabilities detected.")
	}
}

// Function to test Time-based SQLi
func testTimeBasedSQLi(urlStr, paramName string, payloads []string, headers map[string]string, sleepTime int, vulnerabilities *[]string) {
	found := false
	for _, payload := range payloads {
		injectedPayload := strings.Replace(payload, "[SLEEPTIME]", fmt.Sprintf("%d", sleepTime), -1)

		responseTime, _, err := sendTimedRequest(urlStr, paramName, injectedPayload, headers)
		if err != nil {
			fmt.Println("Error sending request:", err)
			continue
		}

		if int(responseTime.Seconds()) >= sleepTime {
			vulnerability := fmt.Sprintf("Time-based SQLi detected with payload '%s'", injectedPayload)
			fmt.Println(vulnerability)
			*vulnerabilities = append(*vulnerabilities, vulnerability)
			found = true
		}
	}

	if !found {
		fmt.Println("No Time-based SQLi vulnerabilities detected.")
		*vulnerabilities = append(*vulnerabilities, "No Time-based SQLi vulnerabilities detected.")
	}
}

// Function to test Error-based SQLi
func testErrorBasedSQLi(urlStr, paramName string, payloads []string, headers map[string]string, vulnerabilities *[]string) {
	found := false
	errorPatterns := []string{
		"sql syntax", "warning", "mysql", "microsoft sql server", "unclosed quotation mark",
	}

	for _, payload := range payloads {
		_, bodyString, err := sendTimedRequest(urlStr, paramName, payload, headers)
		if err != nil {
			fmt.Println("Error sending request:", err)
			continue
		}

		for _, pattern := range errorPatterns {
			if strings.Contains(strings.ToLower(bodyString), pattern) {
				vulnerability := fmt.Sprintf("Error-based SQLi detected with payload '%s'", payload)
				fmt.Println(vulnerability)
				*vulnerabilities = append(*vulnerabilities, vulnerability)
				found = true
				break
			}
		}
	}

	if !found {
		fmt.Println("No Error-based SQLi vulnerabilities detected.")
		*vulnerabilities = append(*vulnerabilities, "No Error-based SQLi vulnerabilities detected.")
	}
}

// Function to generate a vulnerability report
func generateReport(reportFile string, urlStr string, paramName string, vulnerabilities []string) {
	f, err := os.Create(reportFile)
	if err != nil {
		fmt.Println("Error creating the report:", err)
		return
	}
	defer f.Close()

	f.WriteString("SQLi Vulnerability Report\n")
	f.WriteString(fmt.Sprintf("URL: %s\n", urlStr))
	f.WriteString(fmt.Sprintf("Tested parameter: %s\n\n", paramName))
	f.WriteString("Found vulnerabilities:\n")

	if len(vulnerabilities) == 0 {
		f.WriteString("No vulnerabilities were found.\n")
	} else {
		for _, vulnerability := range vulnerabilities {
			f.WriteString(fmt.Sprintf("- %s\n", vulnerability))
		}
	}

	fmt.Printf("Report generated: %s\n", reportFile)
}

func main() {
	// Parsing CLI arguments
	urlStr := flag.String("url", "", "The target URL to check for SQLi vulnerabilities.")
	paramName := flag.String("param", "", "The name of the parameter to be tested.")
	userAgent := flag.String("user-agent", "default", "The User-Agent to use in requests. Use 'random' for a random User-Agent.")
	delay := flag.Int("delay", 5, "Waiting time in seconds for Time-based SQLi tests.")
	techniques := flag.String("techniques", "BTE", "SQLi techniques to test: B=Boolean, T=Time, E=Error.")
	reportFile := flag.String("report", "report.txt", "File to save the vulnerability report.")

	flag.Usage = func() {
		fmt.Println("Tool usage:")
		fmt.Println("  go run main.go --url=<URL> --param=<param> [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  --url            The target URL to check for SQLi vulnerabilities.")
		fmt.Println("  --param          The name of the parameter to be tested.")
		fmt.Println("  --user-agent     The User-Agent to use in requests. Use 'random' for a random User-Agent.")
		fmt.Println("  --delay          Waiting time in seconds for Time-based SQLi tests.")
		fmt.Println("  --techniques     SQLi techniques to test: B=Boolean, T=Time, E=Error.")
		fmt.Println("  --report         File to save the vulnerability report (default: report.txt).")
		fmt.Println("\nUsage examples:")
		fmt.Println("  Test a URL with all techniques using a random User-Agent:")
		fmt.Println("    go run main.go --url=http://example.com --param=id --user-agent=random")
		fmt.Println("  Test a URL with Boolean and Error techniques only:")
		fmt.Println("    go run main.go --url=http://example.com --param=id --techniques=BE")
	}

	flag.Parse()

	if *urlStr == "" || *paramName == "" {
		fmt.Println("Error: you must specify the URL and the name of the parameter to be tested.")
		flag.Usage()
		return
	}

	// User-Agent configuration
	headers := map[string]string{}
	if *userAgent == "random" {
		headers["User-Agent"] = getRandomUserAgent()
	} else if *userAgent == "default" {
		headers["User-Agent"] = "SQLi-Scanner"
	} else {
		headers["User-Agent"] = *userAgent
	}

	param := Parameter{Key: *paramName, Value: "1", Type: "GET"}

	// List of detected vulnerabilities
	var vulnerabilities []string

	// 1. Basic check
	basicCheckResponse := basicCheck(*urlStr, headers, param)
	if basicCheckResponse != nil {
		fmt.Println("Basic check completed.")
		if basicCheckResponse.PossibleDBMS != "" {
			vulnerabilities = append(vulnerabilities, fmt.Sprintf("Parameter %s might be injectable (Possible DBMS: %s)", param.Key, basicCheckResponse.PossibleDBMS))
		}
	}

	// 2. Extended DBMS check, if necessary
	if basicCheckResponse != nil && basicCheckResponse.PossibleDBMS != "" {
		detectedDBMS := extendedDBMSCheck(*urlStr, param, basicCheckResponse.PossibleDBMS, headers)
		if detectedDBMS != "" {
			vulnerabilities = append(vulnerabilities, fmt.Sprintf("Detected DBMS: %s", detectedDBMS))
		}
	}

	// 3. Test Boolean-based SQLi
	if strings.Contains(*techniques, "B") {
		testBooleanBasedSQLi(*urlStr, param.Key, payload.BooleanPayloads, headers, &vulnerabilities)
	}

	// 4. Test Time-based SQLi
	if strings.Contains(*techniques, "T") {
		testTimeBasedSQLi(*urlStr, param.Key, payload.TimePayloads, headers, *delay, &vulnerabilities)
	}

	// 5. Test Error-based SQLi
	if strings.Contains(*techniques, "E") {
		testErrorBasedSQLi(*urlStr, param.Key, payload.ErrorPayloads, headers, &vulnerabilities)
	}

	// Generate the report
	generateReport(*reportFile, *urlStr, *paramName, vulnerabilities)
}
