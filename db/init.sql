CREATE TABLE roles (
    id   SERIAL PRIMARY KEY,
    name VARCHAR(30) UNIQUE NOT NULL
);

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50) UNIQUE NOT NULL,
    email         VARCHAR(120) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role_id       INT NOT NULL REFERENCES roles(id),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE data_sources (
    id         SERIAL PRIMARY KEY,
    name       VARCHAR(80) NOT NULL,
    type       VARCHAR(30) NOT NULL,
    config     JSONB NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    last_event TIMESTAMPTZ
);

CREATE TABLE alerts (
    id           BIGSERIAL PRIMARY KEY,
    es_alert_id  TEXT,
    incident_id  BIGINT,
    alert_type   VARCHAR(40) NOT NULL,
    severity     VARCHAR(10) NOT NULL,
    score        REAL NOT NULL,
    client_ip    INET,
    status       VARCHAR(20) NOT NULL DEFAULT 'new',
    assigned_to  INT REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE whitelist (
    id         SERIAL PRIMARY KEY,
    kind       VARCHAR(20) NOT NULL,
    value      TEXT NOT NULL,
    reason     TEXT,
    created_by INT REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE model_registry (
    id         SERIAL PRIMARY KEY,
    name       VARCHAR(60) NOT NULL,
    version    VARCHAR(20) NOT NULL,
    algorithm  VARCHAR(40) NOT NULL,
    metrics    JSONB,
    file_path  TEXT NOT NULL,
    is_active  BOOLEAN NOT NULL DEFAULT FALSE,
    trained_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    user_id    INT REFERENCES users(id),
    action     VARCHAR(60) NOT NULL,
    details    JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO roles (name) VALUES ('admin'), ('analyst');
