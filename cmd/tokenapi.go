package main

import (
	"flag"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/joho/godotenv"
	_ "github.com/nabishec/tokenapi/docs"
	"github.com/nabishec/tokenapi/internal/lib"
	"github.com/nabishec/tokenapi/internal/server/handlers/auth"
	"github.com/nabishec/tokenapi/internal/storage/postgresql/db"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title Auth Tokens
// @version 1.0
// @description API Server for Auth
// @contact.email nabishec@mail.ru
// @host localhost:8080
func main() {
	//TODO: init logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	debug := flag.Bool("d", false, "set log level to debug")
	easyReading := flag.Bool("r", false, "set console writer")
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	//for easy reading
	if *easyReading {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	//TODO: init config
	err := godotenv.Load("./configs/configuration.env")
	if err != nil {
		log.Error().Err(err).Msg("don't found configuration")
		os.Exit(1)
	}

	//TODO: init storage postgresql
	log.Info().Msg("Init storage")
	storage, err := db.NewDatabase()
	if err != nil {
		log.Error().AnErr(lib.ErrReader(err)).Msg("Failed init storage")
		os.Exit(1)
	}
	log.Info().Msg("Storage init successful")
	//TODO: init middleweare
	router := chi.NewRouter()

	tokenIssuance := auth.NewTokenIssuance(storage)
	tokenRefresh := auth.NewRefresh(storage)

	router.Get("/swagger/*", httpSwagger.WrapHandler)
	router.Post("/tokenapi/v1/auth/token", tokenIssuance.ReturnToken)
	router.Post("/tokenapi/v1/auth/refresh", tokenRefresh.RefreshToken)

	//TODO: run server
	wrTime, err := time.ParseDuration(os.Getenv("TIMEOUT"))
	if err != nil {
		log.Error().Err(err).Msg("timeout not received from env")
		wrTime = 4 * time.Second
	}
	idleTime, err := time.ParseDuration(os.Getenv("IDLE_TIMEOUT"))
	if err != nil {
		log.Error().Err(err).Msg("idle timeout not received from env")
		idleTime = 60 * time.Second
	}

	srv := &http.Server{
		Addr:         os.Getenv("ADDRESS"),
		Handler:      router,
		ReadTimeout:  wrTime,
		WriteTimeout: wrTime,
		IdleTimeout:  idleTime,
	}
	log.Info().Msgf("Starting server on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Error().Msg("failed to start server")
		os.Exit(1)
	}

	log.Error().Msg("Program ended")
}
