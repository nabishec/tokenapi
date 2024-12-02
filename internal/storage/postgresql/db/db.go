package db

import (
	"fmt"
	"os"

	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/nabishec/tokenapi/internal/storage/postgresql/migrations"

	"github.com/rs/zerolog/log"
)

type Database struct {
	dataSourceName string
	DB             *sqlx.DB
}

func NewDatabase() (*Database, error) {
	log.Info().Msg("Connecting to database")

	log.Debug().Msg("Init database")
	var database Database

	config, err := newDSN()
	if err != nil {
		return nil, err
	}

	err = database.connectDatabase(config)
	if err != nil {
		return nil, err
	}

	err = migrations.MigrationsUp(database.DB, database.dataSourceName)
	if err != nil {
		return nil, err
	}

	log.Info().Msg("Сonnection to the database is successful")
	return &database, err
}

func (db *Database) connectDatabase(config string) error {
	const op = "internal.storage.postgresql.db.connectDatabase()"

	log.Debug().Msg("Attempting to connect to database")

	db.dataSourceName = config

	var connectError error
	db.DB, connectError = sqlx.Connect("pgx", db.dataSourceName)
	if connectError != nil {
		return fmt.Errorf("%s:%w", op, connectError)
	}

	log.Debug().Msg("Connecting to database is successfully")
	return nil
}

func (db *Database) PingDatabase() error {
	const op = "internal.storage.postgresql.db.PingDatabase()"

	log.Info().Msg("Attempting to ping Database")
	if db.DB == nil {
		return fmt.Errorf("%s:%s", op, "database isn`t established")
	}

	var pingError = db.DB.Ping()
	if pingError != nil {
		return fmt.Errorf("%s:%w", op, pingError)
	}

	log.Info().Msg("Ping database is successful")
	return nil
}

func (db *Database) CloseDatabase() error {
	const op = "internal.storage.postgresql.db.CloseDatabase()"

	log.Info().Msg("Attempting to close database")
	var closingError = db.DB.Close()
	if closingError != nil {
		return fmt.Errorf("%s:%w", op, closingError)
	}
	log.Info().Msg("Successful closing of database")
	return nil
}

func newDSN() (string, error) {
	const op = "internal.storage.postgresql.db.NewDSN()"

	log.Debug().Msg("Reading dsn from env variables")
	dsnProtocol := os.Getenv("DB_PROTOCOL")
	if dsnProtocol == "" {
		return "", fmt.Errorf("%s:%s", op, "DB_PROTOCOL isn't set")
	}

	dsnUserName := os.Getenv("DB_USER")
	if dsnUserName == "" {
		return "", fmt.Errorf("%s:%s", op, "DB_USER isn't set")
	}

	dsnPassword := os.Getenv("DB_PASSWORD")
	if dsnPassword == "" {
		return "", fmt.Errorf("%s:%s", op, "DB_PASSWORD isn't set")
	}

	dsnHost := os.Getenv("DB_HOST")
	if dsnHost == "" {
		return "", fmt.Errorf("%s:%s", op, "DB_HOST isn't set")
	}

	dsnPort := os.Getenv("DB_PORT")
	if dsnPort == "" {
		return "", fmt.Errorf("%s:%s", op, "DB_PORT isn't set")
	}

	dsnDBName := os.Getenv("DB_NAME")
	if dsnDBName == "" {
		return "", fmt.Errorf("%s:%s", op, "DB_NAME isn't set")
	}

	dsnOptions := os.Getenv("DB_OPTIONS")
	if dsnOptions == "" {
		return "", fmt.Errorf("%s:%s", op, "DB_OPTIONS isn't set")
	}

	dsn := dsnProtocol + "://" + dsnUserName + ":" + dsnPassword + "@" +
		dsnHost + ":" + dsnPort + "/" + dsnDBName + "?" + dsnOptions

	log.Debug().Msg("Reading dsn is successful")
	return dsn, nil
}
