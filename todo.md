# Todo list

- Authentication

- Logging

  Implements logging with options to log to stdout and/or to a logfile and/or
  to an external target such as victoria logs.
  The logfile shoule be rotated based on size or age.


Configuration file
```
type Config struct {
    Domain        string `json:"domain"`
    CertFile      string `json:"cert_file"`
    KeyFile       string `json:"key_file"`
    ListenAddr    string `json:"listen_addr"`
    AdminAddr     string `json:"admin_addr"`
    UpstreamDNS   string `json:"upstream_dns"`
    UpdatePeriod  int    `json:"update_period"`
    ExcludedPorts []int  `json:"excluded_ports,omitempty"`
    HostIP        string `json:"host_ip,omitempty"`
    AliasFile     string `json:"alias_file,omitempty"`

    Log struct {
        Stdout struct {
            Enabled bool `json:"enabled"`
        } `json:"stdout"`
        File struct {
            Enabled  bool   `json:"enabled"`
            Filename string `json:"filename"`
            Rotation struct {
                SizeMB     int `json:"size_mb"`
                MaxBackups int `json:"max_backups"`
                MaxAgeDays int `json:"max_age_days"`
            } `json:"rotation"`
        } `json:"file"`
        Victoria struct {
            Enabled bool   `json:"enabled"`
            URL     string `json:"url"`
            Labels  string `json:"labels"`
        } `json:"victoria"`
    } `json:"log"`
}
```

Intialize logger
```
import (
    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
    "gopkg.in/natefinch/lumberjack.v2"
    "os"
)

var logger *zap.Logger

func initLogger(cfg Config) {
    cores := []zapcore.Core{}
    encoderCfg := zap.NewProductionEncoderConfig()
    encoderCfg.TimeKey = "ts"
    encoder := zapcore.NewJSONEncoder(encoderCfg)

    // Stdout
    if cfg.Log.Stdout.Enabled {
        cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapcore.InfoLevel))
    }

    // File with rotation
    if cfg.Log.File.Enabled {
        w := &lumberjack.Logger{
            Filename:   cfg.Log.File.Filename,
            MaxSize:    cfg.Log.File.Rotation.SizeMB,
            MaxBackups: cfg.Log.File.Rotation.MaxBackups,
            MaxAge:     cfg.Log.File.Rotation.MaxAgeDays,
            Compress:   true,
        }
        cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(w), zapcore.InfoLevel))
    }

    // Victoria (Loki) writer
    if cfg.Log.Victoria.Enabled {
        cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(NewVictoriaWriter(cfg.Log.Victoria)), zapcore.InfoLevel))
    }

    if len(cores) == 0 {
        // No logging enabled
        logger = zap.NewNop()
        return
    }

    combined := zapcore.NewTee(cores...)
    logger = zap.New(combined)
}
```

Replace all calls to log.Printf with calls like this:
```
logger.Info("HTTPS reverse proxy running",
    zap.String("addr", cfg.ListenAddr),
    zap.String("cert", cfg.CertFile),
    zap.String("key", cfg.KeyFile),
)

logger.Error("proxy error",
    zap.String("host", host),
    zap.String("target", target),
    zap.Error(e),
)

logger.Info("[DNS] Query received",
    zap.String("remote", w.RemoteAddr().String()),
    zap.Int("questions", len(r.Question)),
)
```


Sample configuration file
```
{
  "domain": "z90.org",
  "cert_file": "./certs/z90.org.crt",
  "key_file": "./certs/z90.org.key",
  "listen_addr": ":443",
  "admin_addr": ":6060",
  "upstream_dns": "8.8.8.8:53",
  "update_period": 10,
  "excluded_ports": [22],
  "log": {
    "stdout": { "enabled": true },
    "file": { "enabled": true, "filename": "ddp.log",
      "rotation": { "size_mb": 10, "max_backups": 5, "max_age_days": 7 }
    },
    "victoria": { "enabled": false, "url": "http://victoria.local:3100/api/v1/push", "labels": "{app=\"ddp\"}" }
  }
}
```




