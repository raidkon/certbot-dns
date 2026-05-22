package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	legolog "github.com/go-acme/lego/v4/log"
	"log/slog"
)

// LevelFatal — минимальный уровень «только критические»; записи с этим уровнем + os.Exit в LogFatal.
const LevelFatal = slog.Level(12)

type loggingSetup struct {
	Min       slog.Level
	AddSource bool
}

func parseLoggingSetup(s string) (loggingSetup, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return loggingSetup{slog.LevelDebug, true}, nil
	case "verbose":
		// Как debug по фильтру сообщений, без путей исходников в каждой строке.
		return loggingSetup{slog.LevelDebug, false}, nil
	case "info":
		return loggingSetup{slog.LevelInfo, false}, nil
	case "warning", "warn":
		return loggingSetup{slog.LevelWarn, false}, nil
	case "error":
		return loggingSetup{slog.LevelError, false}, nil
	case "fatal":
		return loggingSetup{LevelFatal, false}, nil
	default:
		return loggingSetup{}, fmt.Errorf("runtime.loglevel: неизвестное значение %q (допустимо: debug, verbose, info, warning, error, fatal)", s)
	}
}

func initAppLogging(cfg *Config) error {
	setup, err := parseLoggingSetup(cfg.Runtime.Loglevel)
	if err != nil {
		return err
	}
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     setup.Min,
		AddSource: setup.AddSource,
	})
	slog.SetDefault(slog.New(h))
	legolog.Logger = legoSlogAdapter{}
	slog.Info("логирование инициализировано", "loglevel", cfg.Runtime.Loglevel, "acme_directory", cfg.ACME.Directory, "runtime_mode", cfg.Runtime.Mode)
	return nil
}

// legoSlogAdapter перенаправляет lego/log в slog (уровень по префиксу или debug).
type legoSlogAdapter struct{}

func (legoSlogAdapter) Printf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	switch {
	case strings.HasPrefix(msg, "[WARN]"):
		slog.Warn(strings.TrimSpace(strings.TrimPrefix(msg, "[WARN]")))
	case strings.HasPrefix(msg, "[INFO]"):
		slog.Info(strings.TrimSpace(strings.TrimPrefix(msg, "[INFO]")))
	default:
		slog.Debug(msg)
	}
}

func (legoSlogAdapter) Print(args ...any) { slog.Info(fmt.Sprint(args...)) }
func (legoSlogAdapter) Println(args ...any) {
	slog.Info(strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}
func (legoSlogAdapter) Fatal(args ...any) { logFatal(fmt.Sprint(args...)) }
func (legoSlogAdapter) Fatalln(args ...any) {
	logFatal(strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}
func (legoSlogAdapter) Fatalf(format string, args ...any) { logFatal(fmt.Sprintf(format, args...)) }

func logFatal(msg string) {
	slog.Log(context.Background(), LevelFatal, msg)
	os.Exit(1)
}
