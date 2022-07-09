package main

import (
	"flag"
	"fmt"

	"github.com/tufanbarisyildirim/gonginx"
	"github.com/tufanbarisyildirim/gonginx/parser"
)

var (
	flagFilePath          string
	flagAccessLogFilePath string
)

func init() {
	flag.StringVar(&flagFilePath, "file", "/etc/nginx/nginx.conf", "nginx config file path")
	flag.StringVar(&flagAccessLogFilePath, "access-log", "/var/log/nginx/access.log", "nginx access log file path")
	flag.Parse()
}

func main() {
	config, err := parse(flagFilePath)
	if err != nil {
		panic(err)
	}

	setWorkerRLimitNofile(config)
	setWorkerConnections(config)
	setKataribeLogging(config)

	err = gonginx.WriteConfig(config, gonginx.NewStyle(), true)
	if err != nil {
		panic(err)
	}
}

func parse(filePath string) (*gonginx.Config, error) {
	p, err := parser.NewParser(filePath, parser.WithIncludeParsing())
	if err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	config := p.Parse()

	return config, nil
}

const (
	workerRlimitNofile      = "worker_rlimit_nofile"
	workerRlimitNofileValue = "4096"
)

func setWorkerRLimitNofile(config *gonginx.Config) {
	directives := config.FindDirectives(workerRlimitNofile)
	if len(directives) == 0 {
		config.Directives = append(config.Directives, &gonginx.Directive{
			Name:       workerRlimitNofile,
			Parameters: []string{workerRlimitNofileValue},
		})

		return
	}

	directive, ok := directives[0].(*gonginx.Directive)
	if !ok {
		return
	}

	directive.Parameters = []string{workerRlimitNofileValue}
}

const (
	events                 = "events"
	workerConnections      = "worker_connections"
	workerConnectionsValue = "1024"
)

func setWorkerConnections(config *gonginx.Config) {
	directives := config.FindDirectives(events)
	if len(directives) == 0 {
		config.Directives = append(config.Directives, &gonginx.Directive{
			Name: "events",
			Block: &gonginx.Block{
				Directives: []gonginx.IDirective{
					&gonginx.Directive{
						Name:       workerConnections,
						Parameters: []string{workerConnectionsValue},
					},
				},
			},
		})

		return
	}

	block, ok := directives[0].GetBlock().(*gonginx.Block)
	if !ok {
		return
	}

	block.Directives = append(block.Directives, &gonginx.Directive{
		Name:       workerConnections,
		Parameters: []string{workerConnectionsValue},
	})
}

const (
	httpDirective  = "http"
	logFormat      = "log_format"
	logKey         = "kataribe"
	logFormatValue = `'$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time'`
	accessLog      = "access_log"
)

func setKataribeLogging(config *gonginx.Config) {
	directives := config.FindDirectives(httpDirective)
	if len(directives) == 0 {
		return
	}

	for _, directive := range directives {
		httpBlock, ok := directive.GetBlock().(*gonginx.Block)
		if !ok {
			continue
		}

		directives = httpBlock.FindDirectives(logFormat)
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       logFormat,
				Parameters: []string{logKey, logFormatValue},
			}, &gonginx.Directive{
				Name:       accessLog,
				Parameters: []string{flagAccessLogFilePath, logKey},
			})

			return
		}

		httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
			Name:       logFormat,
			Parameters: []string{logKey, logFormatValue},
		})

		httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
			Name:       accessLog,
			Parameters: []string{flagAccessLogFilePath, logKey},
		})
	}
}
