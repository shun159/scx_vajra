package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

type CustomFormatter struct{}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var colorCode string

	switch entry.Level {
	case logrus.DebugLevel, logrus.TraceLevel:
		colorCode = "\x1b[37m"
	case logrus.InfoLevel:
		colorCode = "\x1b[36m"
	case logrus.WarnLevel:
		colorCode = "\x1b[33m"
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		colorCode = "\x1b[31m"
	default:
		colorCode = "\x1b[0m"
	}

	timestamp := entry.Time.Format("2006-01-02T15:04:05Z07:00")
	levelText := strings.ToUpper(entry.Level.String())
	if len(levelText) > 4 {
		levelText = levelText[:4]
	}
	logLine := fmt.Sprintf("%s[%s] [%s] %s\x1b[0m\n",
		colorCode, timestamp, levelText, entry.Message)

	return []byte(logLine), nil
}

var log = logrus.New()

func initLogger() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&CustomFormatter{})
	log.SetLevel(logrus.InfoLevel)
}

func init() {
	initLogger()
}
