CREATE TABLE Users (
    user_id  UUID PRIMARY KEY,
    user_mail TEXT UNIQUE NOT NULL
);

CREATE TABLE Refresh_tokens (
    token_id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES Users(user_id) UNIQUE NOT NULL,
    ref_hash TEXT UNIQUE NOT NULL,
    ip TEXT NOT NULL,
    jti TEXT NOT NULL,
    exp TIMESTAMP  WITH TIME ZONE NOT NULL DEFAULT NOW()
);