DROP TABLE IF EXISTS users ;
CREATE TABLE users(
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password VARCHAR(256) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    created_on TIMESTAMP NOT NULL,
    last_login TIMESTAMP NOT NULL,
    client_public_key VARCHAR(2048) NOT NULL
);

