package main

import (
	"flag"
	"fmt"

	"github.com/tufanbarisyildirim/gonginx"
	"github.com/tufanbarisyildirim/gonginx/parser"
)

var (
	flagFilePath string
)

func init() {
	flag.StringVar(&flagFilePath, "file", "/etc/nginx/nginx.conf", "nginx config file path")
	flag.Parse()
}

func main() {
	config, err := parse(flagFilePath)
	if err != nil {
		panic(err)
	}

	setWorkerRLimitNofile(config)
	setWorkerConnections(config)

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
