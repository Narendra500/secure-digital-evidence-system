package config

import (
	"os"
	"time"
)

type EnvDBConfig struct {
	host            string
	port            string
	username        string
	password        string
	database        string
	maxConns        int32
	minConns        int32
	maxConnIdleTime time.Duration
}

func NewEnvDBConfig(maxConns int32, minConns int32, maxConnIdleTime time.Duration) *EnvDBConfig {

	return &EnvDBConfig{
		host:            os.Getenv("DB_HOST"),
		port:            os.Getenv("DB_PORT"),
		username:        os.Getenv("DB_USERNAME"),
		password:        os.Getenv("DB_PASSWORD"),
		database:        os.Getenv("DB_DATABASE"),
		maxConns:        maxConns,
		minConns:        minConns,
		maxConnIdleTime: maxConnIdleTime,
	}
}

func (c *EnvDBConfig) GetHost() string {
	return c.host
}

func (c *EnvDBConfig) GetPort() string {
	return c.port
}

func (c *EnvDBConfig) GetUsername() string {
	return c.username
}

func (c *EnvDBConfig) GetPassword() string {
	return c.password
}

func (c *EnvDBConfig) GetDatabase() string {
	return c.database
}

func (c *EnvDBConfig) GetMaxConns() int32 {
	return c.maxConns
}

func (c *EnvDBConfig) GetMinConns() int32 {
	return c.minConns
}

func (c *EnvDBConfig) GetMaxConnIdleTime() time.Duration {
	return c.maxConnIdleTime
}
