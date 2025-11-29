# Todo list

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
    "victoria": { "enabled": false, "url": "http://victoria.local:3100/loki/api/v1/push", "labels": "{app=\"ddp\"}" }
  }
}
```




- Targets

  Make it possible to list all targets and select which of the tagets should
  be the active target.



Extend Host Entry with ActiveIndex:
```
type HostEntry struct {
    Name        string   `json:"name"`
    Url         string   `json:"url"`
    Targets     []string `json:"targets"`
    Aliases     []string `json:"aliases,omitempty"`
    ActiveIndex int      `json:"active_index"`
}
```

Modify the reverse proxy and change:

```
target := h.Targets[0]
```

with

```
idx := h.ActiveIndex
if idx < 0 || idx >= len(h.Targets) {
    http.Error(w, "invalid active target", http.StatusInternalServerError)
    return
}
target := h.Targets[idx]
```


Add new API endpoint to list the targets.

```
func listTargets(w http.ResponseWriter, r *http.Request) {
    name := strings.TrimPrefix(r.URL.Path, "/hosts/")
    name = strings.TrimSuffix(name, "/targets")

    hostsLock.RLock()
    h, ok := hosts[name]
    hostsLock.RUnlock()

    if !ok {
        http.Error(w, "host not found", http.StatusNotFound)
        return
    }

    resp := map[string]interface{}{
        "name":    h.Name,
        "active":  h.ActiveIndex,
        "targets": h.Targets,
    }

    _ = json.NewEncoder(w).Encode(resp)
}
```

Add new API endpoint to set active target.

```
func setActiveTarget(w http.ResponseWriter, r *http.Request) {
    parts := strings.Split(r.URL.Path, "/")
    if len(parts) != 4 || parts[3] != "target" {
        http.Error(w, "invalid path", http.StatusBadRequest)
        return
    }
    hostname := parts[2]

    var body struct {
        ActiveIndex int `json:"active_index"`
    }

    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    hostsLock.Lock()
    h, ok := hosts[hostname]
    if !ok {
        hostsLock.Unlock()
        http.Error(w, "host not found", http.StatusNotFound)
        return
    }

    if body.ActiveIndex < 0 || body.ActiveIndex >= len(h.Targets) {
        hostsLock.Unlock()
        http.Error(w, "invalid index", http.StatusBadRequest)
        return
    }

    h.ActiveIndex = body.ActiveIndex
    hostsLock.Unlock()

    _ = json.NewEncoder(w).Encode(h)
}
```

Add the new targets to startAdminAPI.

```
mux.HandleFunc("/hosts/", func(w http.ResponseWriter, r *http.Request) {
    switch {
    case strings.HasSuffix(r.URL.Path, "/alias") && r.Method == "POST":
        addAlias(w, r)
    case strings.HasSuffix(r.URL.Path, "/targets") && r.Method == "GET":
        listTargets(w, r)
    case strings.HasSuffix(r.URL.Path, "/target") && r.Method == "POST":
        setActiveTarget(w, r)
    case r.Method == "DELETE":
        deleteHost(w, r)
    default:
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    }
})
```


Update docker watcher.
Replace

```
hosts[h.Name] = h
```

with

```
existing, ok := hosts[h.Name]
if ok {
    existing.Targets = appendIfMissing(existing.Targets, target)
} else {
    h.ActiveIndex = 0
    hosts[h.Name] = h
}
```


Add target command to ddpctl.


