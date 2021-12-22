########## DATABASE QUERIES AND INSERT ##########

def db_execute_query(db_connection, query, get): # get is True if we expect a reply
    cur = db_connection.cursor()
    cur.execute(query)
    if get:
        res = cur.fetchall()
    cur.close()
    if get:
        return res
    else:
        db_connection.commit()

def db_get_users(db_connection) :
    query = "SELECT username FROM users ;"
    res = db_execute_query(db_connection, query, 1)
    
    cred = []
    for user in res :
        cred.append(user[0])
    return cred
    
def db_get_password_from_username(db_connection, username) :
    query = """
    SELECT password FROM users WHERE username = '{}'
    """.format(username)
    res = db_execute_query(db_connection, query, 1)
    return res[0][0] # We want the first (and only) parameter of the first (and only) match

def db_update_last_login(db_connection, username) :
    query = """
    UPDATE users
    SET last_login = now()
    WHERE username = '{}'
    """.format(username)
    db_execute_query(db_connection, query, 0)
    
def db_get_publickey_from_username(db_connection, username):
    query = """
    SELECT client_public_key FROM users WHERE username = '{}'
    """.format(username)
    res = db_execute_query(db_connection, query, 1)
    return res[0][0]
    
def db_get_salt_from_username(db_connection, username):
    query = """
    SELECT salt FROM users WHERE username = '{}'
    """.format(username)

    try: # If the user already exists
        res = db_execute_query(db_connection, query, 1)
        return res[0][0]
    except: # Else the salt return will anyway not be used
        return (str.encode("a")).hex()
        
def db_get_id_from_username(db_connection, username):
    query = """
    SELECT user_id FROM users WHERE username='{}'
    """.format(username)
    res = db_execute_query(db_connection, query, 1)
    return res[0][0]

def db_get_messages_from_two_ids(db_connection, id1, id2) :
    query = """
    SELECT u1.username as from , u2.username as to, m.content, to_char(m.time, 'DD-MM-YYYY HH24:MI:SS')
    FROM messages m, users u1 , users u2
    WHERE ((m.from_id = {} AND m.to_id = {})
        OR (m.from_id = {} AND m.to_id = {}))
        AND (m.from_id = u1.user_id AND m.to_id = u2.user_id)
    ORDER BY time
    /* LIMIT 20*/
        ;
    """.format(id1, id2, id2, id1)
    res = db_execute_query(db_connection, query, 1)
    
    return res
    
def db_insert_new_user(db_connection, usr, password, salt, public_key_string):
    query = """
    INSERT INTO users(username, password, salt, created_on, last_login, client_public_key)
    VALUES ('{}','{}', '{}', now(), now(), '{}');
    """.format(usr, password, salt, public_key_string)
    db_execute_query(db_connection, query, 0)
    
def db_insert_new_message(db_connection, from_usr, to_usr, content):
    query = """INSERT INTO messages(from_id, to_id, content, time)
    VALUES({}, {}, '{}', NOW())
    """.format(db_get_id_from_username(db_connection, from_usr), db_get_id_from_username(db_connection, to_usr), content)
    db_execute_query(db_connection, query, 0)
