package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
)

func main() {
	var err error
	var accessLogfile string
	var accessLogFD *os.File
	var nssKeylogFile string
	var nssKeylogFD *os.File
	var scanner *bufio.Scanner
	var regex *regexp.Regexp = regexp.MustCompile(`.+fsv:(.+?)\sfcr:(.+?)\sfsk:(.+?)\sbsv:(.+?)\sbcr:(.+?)\sbsk:(.+?)$`)
	var secretsFS map[string]string = make(map[string]string)
	var secretsBS map[string]string = make(map[string]string)
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--access":
			accessLogfile = os.Args[i+1]
			i++
		case "--nsskeylog":
			nssKeylogFile = os.Args[i+1]
			i++
		}
	}
	if accessLogfile == "" {
		log.Fatalln("Please set --access with the access log file path")
	}
	if nssKeylogFile == "" {
		log.Fatalln("Please set --nsskeylog with the nsskeylog file path you want to generate")
	}
	if accessLogFD, err = os.OpenFile(accessLogfile, os.O_RDONLY, 06000); err != nil {
		log.Fatalln(err)
	}
	defer accessLogFD.Close()
	if nssKeylogFD, err = os.OpenFile(nssKeylogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0600); err != nil {
		log.Fatalln(err)
	}
	defer nssKeylogFD.Close()
	scanner = bufio.NewScanner(accessLogFD)
	var groups []string
	for scanner.Scan() {
		if regex.MatchString(scanner.Text()) {
			groups = regex.FindStringSubmatch(scanner.Text())
			if groups[1] == "TLSv1.2" {
				secretsFS[groups[2]] = groups[3]
			}
			if groups[4] == "TLSv1.2" {
				secretsFS[groups[5]] = groups[6]
			}
		}
	}
	for k, v := range secretsFS {
		_, _ = nssKeylogFD.WriteString(fmt.Sprintf("CLIENT_RANDOM %s %s\n", k, v))
	}
	for k, v := range secretsBS {
		_, _ = nssKeylogFD.WriteString(fmt.Sprintf("CLIENT_RANDOM %s %s\n", k, v))
	}
}
