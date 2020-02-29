// Package to experiment with obtaining aws mfa creds & updating local files
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
)

// aws sts get-session-token --serial-number arn:aws:iam::939413442395:mfa/mitchellt8@aetna.com --profile=setup --token-code <code>

const command = "aws"

var subcommands = []string{"sts", "get-session-token"} // sts get-session-token"

var mfaToken, // the actual mfa token
	mfaSerialNumber, // the mfa arn
	inputFile, // where to read the config block with access key and secret key
	outputFile string // where to write the config back

// struct to hold the nested part of the response from the authenticate call
type awsAccessKey struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

// struct to hold the top level response
type creds struct {
	Credentials awsAccessKey
}

// get the user's home dir,
// set default input and output files,
// read flags (w/ defaults)
func init() {
	// two lines to obtain ~ since cmd.Run() doesn't expand it
	usr, _ := user.Current()
	homeDir := usr.HomeDir
	// default to ~/.aws/credentials
	flag.StringVar(&inputFile, "i", filepath.Join(homeDir, "/.aws/credentials"), "input-credentials-file")
	flag.StringVar(&outputFile, "o", filepath.Join(homeDir, "/.aws/credentials"), "output-credentials-file")
	flag.StringVar(&mfaToken, "t", "", "mfa-token")
	flag.StringVar(&mfaSerialNumber, "s", "", "mfa-serial-number")
}

// make sure we have the token and the s/n
func ensureFlags() {
	required := []string{"s", "t"}
	flag.Parse()

	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, req := range required {
		if !seen[req] {
			showUsage(fmt.Sprintf("missing required argument -%s", req))
		}
	}
}

func showUsage(hint string) {
	var usage = "usage: " + filepath.Base(os.Args[0]) + " -s <serialNum> -t <mfaToken>"
	if hint != "" {
		log.Error(hint)
	}
	log.Fatal(usage)
}

func loadCredentialsFile(path string) *ini.File {
	cfg, err := ini.Load(path)
	if err != nil {
		log.Fatal("Failed to read file: %v", err)
	}
	return cfg
}

func updateCredentials(cfg *ini.File, key awsAccessKey) *ini.File {
	cfg.Section("sts").Key("aws_access_key_id").SetValue(key.AccessKeyID)
	cfg.Section("sts").Key("aws_secret_access_key").SetValue(key.SecretAccessKey)
	cfg.Section("sts").Key("aws_session_token").SetValue(key.SessionToken)
	return cfg
}

func writeCredentialsFile(cfg *ini.File, path string) {
	// TODO - make a copy of the file at path if it exists
	err := cfg.SaveTo(path)
	if err != nil {
		log.Fatal("Failed to write file: %v", err)
	}
}

func ensureAwsInstalled() {
	path, err := exec.LookPath(command)
	if err != nil {
		log.Fatal("aws command not found")
	}
	log.WithFields(log.Fields{"exec-path": path}).Info("exec path is ", path)
}

// exec the aws command line and return a token
func authenticate() string {
	log.Printf("executing: %s %v", command, subcommands)
	cmd := exec.Command(command, subcommands...)
	var out, err bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &err
	error := cmd.Run()
	if error != nil {
		log.Println("output: ", err.String())
		log.Fatal("error running command: ", error)
	}
	//log.Println("output: ", out.String())
	return out.String()
}

func parseResponseJSON(responseJSON string) awsAccessKey {
	var cred creds
	json.Unmarshal([]byte(responseJSON), &cred)
	log.Printf("key id: %s", cred.Credentials.AccessKeyID)
	log.Printf("secret: %s", cred.Credentials.SecretAccessKey)
	log.Printf("token: %s", cred.Credentials.SessionToken)
	return cred.Credentials
}

func main() {
	ensureFlags()
	log.WithFields(log.Fields{"sn": mfaSerialNumber,
		"token":      mfaToken,
		"inputfile":  inputFile,
		"outputfile": outputFile}).Info()
	subcommands = append(subcommands, "--serial-number",
		mfaSerialNumber,
		"--profile=setup",
		"--token-code",
		mfaToken)

	ensureAwsInstalled()
	cfg := loadCredentialsFile(inputFile)
	response := authenticate()
	creds := parseResponseJSON(response)
	//	log.WithFields(log.Fields{"json": response}).Info("response")
	cfg = updateCredentials(cfg, creds)
	writeCredentialsFile(cfg, outputFile)
}
