package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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
	setHTTP(config)
	setSSL(config)

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
			})
		} else {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       logFormat,
				Parameters: []string{logKey, logFormatValue},
			})
		}

		directives = httpBlock.FindDirectives(accessLog)
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       logFormat,
				Parameters: []string{logKey, logFormatValue},
			})

			return
		}

		httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
			Name:       accessLog,
			Parameters: []string{flagAccessLogFilePath, logKey},
		})
	}
}

func setHTTP(config *gonginx.Config) {
	directives := config.FindDirectives(httpDirective)
	if len(directives) == 0 {
		return
	}

	for _, directive := range directives {
		httpBlock, ok := directive.GetBlock().(*gonginx.Block)
		if !ok {
			continue
		}

		directives = httpBlock.FindDirectives("sendfile")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "sendfile",
				Parameters: []string{"on"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"on"}
			}
		}

		directives = httpBlock.FindDirectives("tcp_nopush")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "tcp_nopush",
				Parameters: []string{"on"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"on"}
			}
		}

		directives = httpBlock.FindDirectives("tcp_nodelay")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "tcp_nodelay",
				Parameters: []string{"on"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"on"}
			}
		}

		directives = httpBlock.FindDirectives("types_hash_max_size")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "types_hash_max_size",
				Parameters: []string{"2048"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"2048"}
			}
		}

		directives = httpBlock.FindDirectives("server_tokens")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "server_tokens",
				Parameters: []string{"off"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"off"}
			}
		}

		directives = httpBlock.FindDirectives("open_file_cache")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "open_file_cache",
				Parameters: []string{"max=100", "inactive=20s"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"max=100", "inactive=20s"}
			}
		}

		directives = httpBlock.FindDirectives("proxy_buffers")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "proxy_buffers",
				Parameters: []string{"100 32k"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"100 32k"}
			}
		}

		directives = httpBlock.FindDirectives("proxy_buffer_size")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "proxy_buffer_size",
				Parameters: []string{"32k"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"32k"}
			}
		}

		directives = httpBlock.FindDirectives("keepalive_timeout")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "keepalive_timeout",
				Parameters: []string{"65"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"65"}
			}
		}

		directives = httpBlock.FindDirectives("keepalive_requests")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "keepalive_requests",
				Parameters: []string{"10000"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"10000"}
			}
		}

		directives = httpBlock.FindDirectives("http2_max_requests")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "http2_max_requests",
				Parameters: []string{"10000"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"10000"}
			}
		}

		directives = httpBlock.FindDirectives("http2_recv_timeout")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "http2_recv_timeout",
				Parameters: []string{"600s"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"600s"}
			}
		}

		directives = httpBlock.FindDirectives("proxy_cache_path")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "proxy_cache_path",
				Parameters: []string{"/var/cache/nginx/cache", "levels=1:2", "keys_zone=zone1:1m", "max_size=1g", "inactive=1h"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"/var/cache/nginx/cache", "levels=1:2", "keys_zone=zone1:1m", "max_size=1g", "inactive=1h"}
			}
		}
		err := os.MkdirAll("/var/cache/nginx/cache", 0755)
		if err != nil {
			log.Printf("[ERROR] Failed to create /var/cache/nginx/cache: %s\n", err)
		}

		directives = httpBlock.FindDirectives("proxy_temp_path")
		if len(directives) == 0 {
			httpBlock.Directives = append(httpBlock.Directives, &gonginx.Directive{
				Name:       "proxy_temp_path",
				Parameters: []string{"/var/cache/nginx/tmp"},
			})
		} else {
			directive, ok := directives[0].(*gonginx.Directive)
			if ok {
				directive.Parameters = []string{"/var/cache/nginx/tmp"}
			}
		}
		err = os.MkdirAll("/var/cache/nginx/tmp", 0755)
		if err != nil {
			log.Printf("[ERROR] Failed to create /var/cache/nginx/tmp: %s\n", err)
		}
	}
}

func setSSL(config *gonginx.Config) {
	serverDirectives := config.FindDirectives("server")
	if len(serverDirectives) == 0 {
		return
	}

	for _, serverDirective := range serverDirectives {
		serverBlock, ok := serverDirective.GetBlock().(*gonginx.Block)
		if !ok {
			continue
		}

		protoDirectives := serverBlock.FindDirectives("ssl_protocols")
		if len(protoDirectives) == 0 {
			serverBlock.Directives = append(serverBlock.Directives, &gonginx.Directive{
				Name:       "ssl_protocols",
				Parameters: []string{"TLSv1.3", "TLSv1.2"},
			})
		} else {
			protoDirective, ok := protoDirectives[0].(*gonginx.Directive)
			if ok {
				protoDirective.Parameters = []string{"TLSv1.3", "TLSv1.2"}
			}
		}
	}
}
