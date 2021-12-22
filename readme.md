# Welcome to our ELEC-H417 Project
The report has been sent by e-mail and contains the relevant technical points needed to understand our implementation.

## Brief overview and prerequisites

In short terms, our software requires two main parts :
- Server part : located in `server.py`
- Client part : located in `client.py`


In the **server** part, there is :
- Connection to a PostgreSQL DB : 
  - Requires PostgreSQL installed
  - A database configuration file called "database.ini" with the following format 

    ```
    [postgresql]
    host=localhost
    database=networks
    user=postgres      [Or any user]
    password=* * * * * [ Password for this user]
    ```
    
    
  - Psycopg2 to interact with psql from Python
- Socket opening
- Listening to all clients in a thread
- Security aspects (detailed in the report)


In the client part, there is :
- GUI 
  - Requires Python's "Tkinter" module
  - Allows selecting active users, send them messages, and disconnect from the server

- If you desire to connect to a **remote server**, make sure you change the IP in `client.py` from `-1` to the server's IP
- Security aspects (detailed in the report)

## How to
1. Start a PSQL server
2. Create a database called "networks" with the user "postgres"
3. Run the `ddl.sh` script. It will generate the `users` and `messages` tables. You can also call this script whenever you want to reset all the tables.
4. Import the required modules :

    ```
    pip install psycopg2  # Postgres
    pip install tk        # Tkinter
    ```
    
5. Instanciate the server on socket 10000
6. Instanciate a client
7. Register him & log in gom
8. Instanciate another client
9. Register && login home in
10. See that the active users BUT the current users are shown in a panel.
11. Click on a user's name to display their history together
12. Etc.  
