package webui

import (
	"dynamite/config"
	"dynamite/util"
	"dynamite/webui/handlers"
	"dynamite/webui/static"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
)

func withFlavor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.GetFlavor()
		next.ServeHTTP(w, r)
	})
}

// Listen binds Web UI address before anything else touches it,
// fails if another instance is already running
func Listen(address string) (net.Listener, error) {
	if address == "" {
		address = "127.0.0.1:8070"
	}

	return net.Listen("tcp", address)
}

func Run(l net.Listener, conf *config.Config) {
	var err error

	handlers.Init()

	mux := http.NewServeMux()
	hm := withFlavor(mux)
	srv := &http.Server{Addr: l.Addr().String(), Handler: hm}
	handlers.Server = srv
	handlers.Config = conf
	handlers.Version = util.GetVersion()

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(static.FS))))

	mux.HandleFunc("/", handlers.Start)
	mux.HandleFunc("/stop", handlers.Stop)
	mux.HandleFunc("/save-config", handlers.Save)
	mux.HandleFunc("/docs", handlers.Docs)
	mux.HandleFunc("/missionlist", handlers.MissionList)
	mux.HandleFunc("/donate", handlers.Donate)
	mux.HandleFunc("/donated", handlers.Donated)
	mux.HandleFunc("/license", handlers.License)
	mux.HandleFunc("/status", handlers.Status)
	mux.HandleFunc("/healthcheck", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		return
	})

	if err = srv.Serve(l); err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Web UI", "error", err.Error())
			slog.Error("Press Enter to exit.")
			var a []byte
			_, _ = fmt.Scanln(&a)
			os.Exit(1)
		}
	}
}
