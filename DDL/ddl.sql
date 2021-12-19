DROP TABLE IF EXISTS users ;
CREATE TABLE users(
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password VARCHAR(256) NOT NULL,
    created_on TIMESTAMP NOT NULL,
    last_login TIMESTAMP NOT NULL
);