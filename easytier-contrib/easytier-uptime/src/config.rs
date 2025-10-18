use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use easytier::common::config::{ConsoleLoggerConfig, FileLoggerConfig, LoggingConfig};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub health_check: HealthCheckConfig,
    pub logging: LoggingConfig,
    pub cors: CorsConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub path: PathBuf,
    pub max_connections: u32,
}

#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub max_retries: u32,
}

#[derive(Debug, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub enable_compression: bool,
    pub secret_key: String,
    pub jwt_secret: String,
    pub admin_password: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::from_env().unwrap_or_else(|_| Self::default_config())
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, env::VarError> {
        let server_config = ServerConfig {
            host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("SERVER_PORT")
                .map(|s| s.parse().unwrap_or(8080))
                .unwrap_or(8080),
            addr: SocketAddr::from((
                env::var("SERVER_HOST")
                    .unwrap_or_else(|_| "127.0.0.1".to_string())
                    .parse::<IpAddr>()
                    .unwrap(),
                env::var("SERVER_PORT")
                    .map(|s| s.parse().unwrap_or(8080))
                    .unwrap_or(8080),
            )),
        };

        let database_config = DatabaseConfig {
            path: PathBuf::from(
                env::var("DATABASE_PATH").unwrap_or_else(|_| "uptime.db".to_string()),
            ),
            max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                .map(|s| s.parse().unwrap_or(10))
                .unwrap_or(10),
        };

        let health_check_config = HealthCheckConfig {
            interval_seconds: env::var("HEALTH_CHECK_INTERVAL")
                .map(|s| s.parse().unwrap_or(30))
                .unwrap_or(30),
            timeout_seconds: env::var("HEALTH_CHECK_TIMEOUT")
                .map(|s| s.parse().unwrap_or(10))
                .unwrap_or(10),
            max_retries: env::var("HEALTH_CHECK_RETRIES")
                .map(|s| s.parse().unwrap_or(3))
                .unwrap_or(3),
        };

        let logging_config = LoggingConfig {
            file_logger: Some(FileLoggerConfig {
                level: Some(env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string())),
                file: Some("easytier-uptime.log".to_string()),
                ..Default::default()
            }),
            console_logger: Some(ConsoleLoggerConfig {
                level: Some(env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string())),
            }),
        };

        let cors_config = CorsConfig {
            allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            allowed_methods: env::var("CORS_ALLOWED_METHODS")
                .unwrap_or_else(|_| "GET,POST,PUT,DELETE,OPTIONS".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            allowed_headers: env::var("CORS_ALLOWED_HEADERS")
                .unwrap_or_else(|_| "content-type,authorization".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            enabled: env::var("ENABLE_CORS")
                .map(|s| s.parse().unwrap_or(true))
                .unwrap_or(true),
        };

        let security_config = SecurityConfig {
            enable_compression: env::var("ENABLE_COMPRESSION")
                .map(|s| s.parse().unwrap_or(true))
                .unwrap_or(true),
            secret_key: env::var("SECRET_KEY").unwrap_or_else(|_| "default-secret-key".to_string()),
            jwt_secret: env::var("JWT_SECRET").unwrap_or_else(|_| "default-jwt-secret".to_string()),
            admin_password: env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin123".to_string()),
        };

        Ok(AppConfig {
            server: server_config,
            database: database_config,
            health_check: health_check_config,
            logging: logging_config,
            cors: cors_config,
            security: security_config,
        })
    }

    pub fn default_config() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
            },
            database: DatabaseConfig {
                path: PathBuf::from("uptime.db"),
                max_connections: 10,
            },
            health_check: HealthCheckConfig {
                interval_seconds: 30,
                timeout_seconds: 10,
                max_retries: 3,
            },
            logging: LoggingConfig {
                file_logger: Some(FileLoggerConfig {
                    level: Some("info".to_string()),
                    file: Some("easytier-uptime.log".to_string()),
                    ..Default::default()
                }),
                console_logger: Some(ConsoleLoggerConfig {
                    level: Some("info".to_string()),
                }),
            },
            cors: CorsConfig {
                allowed_origins: vec![
                    "http://localhost:3000".to_string(),
                    "http://localhost:8080".to_string(),
                ],
                allowed_methods: vec![
                    "GET".to_string(),
                    "POST".to_string(),
                    "PUT".to_string(),
                    "DELETE".to_string(),
                    "OPTIONS".to_string(),
                ],
                allowed_headers: vec!["content-type".to_string(), "authorization".to_string()],
                enabled: true,
            },
            security: SecurityConfig {
                enable_compression: true,
                secret_key: "default-secret-key".to_string(),
                jwt_secret: "default-jwt-secret".to_string(),
                admin_password: "admin123".to_string(),
            },
        }
    }

    pub fn is_development(&self) -> bool {
        env::var("NODE_ENV").unwrap_or_else(|_| "development".to_string()) == "development"
    }

    pub fn is_production(&self) -> bool {
        env::var("NODE_ENV").unwrap_or_else(|_| "development".to_string()) == "production"
    }
}
