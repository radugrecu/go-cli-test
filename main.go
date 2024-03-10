package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

func main() {

	args := os.Args[1:]

	reportPath := "trivy_sample_report.json"
	if len(args) > 0 {
		reportPath = args[0]
	}
	trivyReport := loadTrivyReport(reportPath)
	printTrivyReport(trivyReport)

}

func loadTrivyReport(reportPath string) trivyTypes.Report {

	file, err := os.Open(reportPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var report trivyTypes.Report
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&report)
	if err != nil {
		log.Fatal(err)
	}

	return report
}

func printTrivyReport(report trivyTypes.Report) {
	for _, result := range report.Results {
		// skip non config/terraform results
		if result.Class != "config" && result.Type != "terraform" {
			log.Printf("%s / %s / %s - not a config/terraform result; skipping", result.Target, result.Type, result.Class)
			continue
		}
		// skip if no misconfigurations
		if len(result.Misconfigurations) == 0 {
			continue
		}

		for _, misconfiguration := range result.Misconfigurations {
			comment := generateErrorMessage(misconfiguration)
			writeMultiLineComment(result.Target, comment, misconfiguration.CauseMetadata.StartLine, misconfiguration.CauseMetadata.EndLine)
		}
	}
}

func generateErrorMessage(misconf trivyTypes.DetectedMisconfiguration) string {
	return fmt.Sprintf(`:warning: trivy found a **%s** severity issue from rule `+"`%s`"+`:
> %s

More information available %s`,
		misconf.Severity, misconf.ID, misconf.Message, formatUrls(misconf.References))
}

func formatUrls(urls []string) string {
	urlList := ""
	for _, url := range urls {
		if urlList != "" {
			urlList += fmt.Sprintf(" and ")
		}
		urlList += fmt.Sprintf("[here](%s)", url)
	}
	return urlList
}

func writeMultiLineComment(filename string, comment string, startline int, endline int) {
	println("--- COMMENT ---")
	println("Filename: " + filename)
	println("Comment: " + comment)
	println("Startline: " + strconv.Itoa(startline) + " Endline: " + strconv.Itoa(endline))
	println("--- END COMMENT ---")
}
