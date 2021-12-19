-- DROP TABLE IF EXISTS users ;
-- CREATE TABLE users(
--     user_id SERIAL PRIMARY KEY,
--     username VARCHAR(64) UNIQUE NOT NULL,
--     password VARCHAR(256) NOT NULL,
--     created_on TIMESTAMP NOT NULL,
--     last_login TIMESTAMP NOT NULL
-- );

DROP TABLE IF EXISTS messages ;
CREATE TABLE messages(
    message_id SERIAL PRIMARY KEY,
    from_id INT NOT NULL,
    to_id INT NOT NULL,
    content VARCHAR(1024),
    time TIMESTAMP NOT NULL,

    CONSTRAINT fk_from_id
        FOREIGN KEY (from_id)
            REFERENCES users(user_id),
    CONSTRAINT fk_to_id
        FOREIGN KEY (to_id)
            REFERENCES users(user_id)
);