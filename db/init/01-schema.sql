-- Runs once, on first initialisation of an empty data directory only.
-- To reseed after changing this file: docker compose down -v && docker compose up -d

CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  -- bcrypt output is always 60 chars, but sizing to 255 leaves room to migrate
  -- to argon2id later without an ALTER on a live table.
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(32)  NOT NULL DEFAULT 'user',
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE products (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(160) NOT NULL,
  category    VARCHAR(64)  NOT NULL,
  price_cents INT          NOT NULL,
  spec_file   VARCHAR(120) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE comments (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  product_id INT       NOT NULL,
  author     VARCHAR(64)  NOT NULL,
  body       TEXT         NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_comment_product FOREIGN KEY (product_id)
    REFERENCES products(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
