package migrations

import (
	"database/sql"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

func MigrationsUp(db *sqlx.DB, dsn string) error {
	const op = "internal.storage.postgresql.migrations.MigrationsUp()"

	log.Info().Msg("Launching migrations up")
	if db == nil {
		return fmt.Errorf("%s:%s", op, "database isn`t established")
	}

	migrationDB, err := connectionForMigration(dsn)
	if err != nil {
		return err
	}

	sqlDatabase := migrationDB.DB
	driver, err := newMigrationDriver(sqlDatabase)
	if err != nil {
		return err
	}

	defer closeMigration(driver, migrationDB, op)

	migration, err := newMigrationInstance(driver)
	if err != nil {
		return err
	}

	err = startMigrationUp(migration)
	if err != nil {
		return err
	}

	log.Info().Msg("Migrations up successfully")
	return nil
}

func MigrationsDown(db *sqlx.DB, dsn string) error {
	const op = "internal.storage.postgresql.migrations.MigrationsDown()"

	log.Info().Msg("Launching migrations down")

	if db == nil {
		return fmt.Errorf("%s:%s", op, "database isn`t established")
	}

	migrationDB, err := connectionForMigration(dsn)
	if err != nil {
		return err
	}

	sqlDatabase := migrationDB.DB
	driver, err := newMigrationDriver(sqlDatabase)
	if err != nil {
		return err
	}

	defer closeMigration(driver, migrationDB, op)

	migration, err := newMigrationInstance(driver)
	if err != nil {
		return err
	}

	err = startMigrationDown(migration)
	if err != nil {
		return err
	}

	log.Info().Msg("Migrations down successfully")
	return nil
}

func connectionForMigration(dsn string) (*sqlx.DB, error) {
	const op = "internal.storage.postgresql.migrations.connectionForMigration()"

	log.Debug().Msg("Creating a migration connection")
	migration, err := sqlx.Connect("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("%s:%w", op, err)
	}

	log.Debug().Msg("Migration connection is successful")
	return migration, nil
}

func newMigrationDriver(db *sql.DB) (database.Driver, error) {
	const op = "internal.storage.postgresql.migrations.newMigrationDriver()"

	log.Debug().Msg("Creating driver for migrations")
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return nil, fmt.Errorf("%s:%w", op, err)
	}

	log.Debug().Msg("Migration driver creation is successful")
	return driver, nil
}

func closeMigration(driver database.Driver, migrationDB *sqlx.DB, op string) {
	op += "closeMigration()"
	if err := driver.Close(); err != nil {
		log.Warn().Msgf("%s:%s", op, "Migration's driver couldn't close")
	}

	if err := migrationDB.Close(); err != nil {
		log.Warn().Msgf("%s:%s", op, "Migration's driver couldn't close")
	}
}

func newMigrationInstance(driver database.Driver) (*migrate.Migrate, error) {
	const op = "internal.storage.postgresql.migrations.newMigrationInstance()"

	log.Debug().Msg("Creating a migration instance")

	migrationExmpl, err := migrate.NewWithDatabaseInstance(
		"file://internal/storage/migration",
		"postgres", driver)

	if err != nil {
		return nil, fmt.Errorf("%s:%s", op, err)
	}

	log.Debug().Msg("Migration instance creation is successful")

	return migrationExmpl, nil
}

func startMigrationUp(migration *migrate.Migrate) error {
	const op = "internal.storage.postgresql.migrations.startMigrationUp()"

	log.Debug().Msg("Attempting to migration up")

	err := migration.Up()
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("%s:%s", op, err)
	}

	if err == migrate.ErrNoChange {
		log.Debug().Msgf("%s:%s", op, "No migrations to apply")
	} else {
		log.Debug().Msgf("%s:%s", op, "Migrations applied successfully")
	}
	return nil
}

func startMigrationDown(migration *migrate.Migrate) error {
	const op = "internal.storage.postgresql.migrations.startMigrationDown()"
	err := migration.Down()

	log.Debug().Msg("Attempting to migration down")

	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("%s:%s", op, err)
	}

	if err == migrate.ErrNoChange {
		log.Debug().Msgf("%s:%s", op, "No migrations to apply")
	} else {
		log.Debug().Msgf("%s:%s", op, "Migrations applied successfully")
	}
	return nil
}
