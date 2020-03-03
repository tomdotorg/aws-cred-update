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
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/ini.v1"
)

// aws sts get-session-token --serial-number arn:aws:iam::939413442395:mfa/mitchellt8@aetna.com --profile=setup --token-code <code>

const command = "aws"

var subcommands = []string{"sts", "get-session-token"} // sts get-session-token"

var mfaToken, // the actual mfa token
	mfaSerialNumber, // the mfa arn
	inputFile, // where to read the config block with access key and secret key
	outputFile, // where to write the config back
	mfaProfile, // block in credentials file with the access and secret keys used to obtain a token
	logLevel string // debug, info, warn, error, fatal

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
	flag.StringVar(&mfaProfile, "p", "setup", "credentials-profile")
	flag.StringVar(&logLevel, "l", "info", "log level (debug, info, warn, error")
}

// make sure we have the token and the s/n and set log level if present
func ensureFlags() {
	required := []string{"s", "t"}
	flag.Parse()
	setLogLevel(logLevel)
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, req := range required {
		if !seen[req] {
			showUsage(fmt.Sprintf("missing required argument -%s", req))
		}
	}
}

func showUsage(hint string) {
	var usage = "usage: " + filepath.Base(os.Args[0]) + " -s <serialNum> -t <mfaToken> " +
		"[ -p <profilename> -l { debug, info, warn, error } -i inputfile -o outputfile ]"
	if hint != "" {
		log.Error(hint)
	}
	log.Fatal(usage)
}

// allow user to pass in a log level
func setLogLevel(flag string) {
	switch flag {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.Warn("invalid log level set: ", flag)
		log.Warn("must be one of { debug, info, warn, error }")
		log.SetLevel(log.InfoLevel)
	}
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

// make sure the aws executable exists
func ensureAwsInstalled() {
	path, err := exec.LookPath(command)
	if err != nil {
		log.Fatal("aws command not found")
	}
	log.Debug("aws exec path is ", path)
}

// exec the aws command line and return a token
func authenticate() string {
	cmd := exec.Command(command, subcommands...)
	log.Debug("executing: ", cmd)
	var out, err bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &err
	error := cmd.Run()
	if error != nil {
		log.Error("output: ", err.String())
		log.Fatal("error running command: ", error)
	}
	log.Debug("output from authenticate(): ", out.String())
	return out.String()
}

func parseResponseJSON(responseJSON string) awsAccessKey {
	var cred creds
	json.Unmarshal([]byte(responseJSON), &cred)
	log.Debug("key id: %s", cred.Credentials.AccessKeyID)
	log.Debug("secret: %s", cred.Credentials.SecretAccessKey)
	log.Debug("token: %s", cred.Credentials.SessionToken)
	return cred.Credentials
}

func writeToConsole(creds awsAccessKey) {
	fmt.Printf("export AWS_ACCESS_KEY_ID=\"%s\"\n", creds.AccessKeyID)
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=\"%s\"\n", creds.SecretAccessKey)
	fmt.Printf("export AWS_SESSION_TOKEN=\"%s\"\n", creds.SessionToken)
}

func main() {
	ensureFlags()
	ensureAwsInstalled()
	log.WithFields(log.Fields{"sn": mfaSerialNumber,
		"token":      mfaToken,
		"profile":    mfaProfile,
		"inputfile":  inputFile,
		"outputfile": outputFile,
		"logLevel":   logLevel}).Debug("parameters and flags")
	subcommands = append(subcommands, "--serial-number", mfaSerialNumber,
		"--profile", mfaProfile,
		"--token-code", mfaToken)
	cfg := loadCredentialsFile(inputFile)
	log.Info("authenticating")
	response := authenticate()
	creds := parseResponseJSON(response)
	log.Debug("response: ", response)
	cfg = updateCredentials(cfg, creds)
	// set the env vars
	writeCredentialsFile(cfg, outputFile)
	writeToConsole(creds)
	log.Info("done - updated ", outputFile)
	t, _ := time.Parse("2006-01-02T15:04:05Z", creds.Expiration)
	log.Info("session expires: ", t.Local().Format("2006-01-02 15:04:05 -0700"))
}
