import sqlite3
import os

DB_FOLDER = "Databases"
USERS_DB_NAME = DB_FOLDER + "/users.sqlite3"
USERS_DB_TABLE_NAME = "users"

USER_TABLE_COLUMNS = 'id INTEGER PRIMARY KEY AUTOINCREMENT, ' \
                      'username text UNIQUE, ' \
                      'password text, ' \
                      'rights text, ' \
                      'password_reset INTEGER'

USER_TABLE_COLUMN_NAMES = "username text UNIQUE,  \
                            password text, \
                            rights text, \
                            password_reset INTEGER"

SERVER_DATABASES_LIST = [USERS_DB_NAME]
SERVER_DATABASES_WITH_TABLES_AND_COLUMNS = [{"db_path": USERS_DB_NAME,
                                            "table_name": USERS_DB_TABLE_NAME,
                                            "table_columns": USER_TABLE_COLUMNS}]

# -------- Setup --------
def check_if_databases_exist(databases_list):
    for database_path in databases_list:
        if not os.path.exists(database_path):
            print("One database doesn't exist.")
            return False
    return True

def check_if_server_databases_exist():
    databases_list = SERVER_DATABASES_LIST
    status = check_if_databases_exist(databases_list)
    return status

def remove_previous_databases(database_paths_list):
    # Temp function: Use for testing
    for database in database_paths_list:
        try:
            os.remove(database)
        except FileNotFoundError:
            print("No database was found at path %s", database)

def cleanup_server_databases():
    databases_list = SERVER_DATABASES_LIST
    remove_previous_databases(databases_list)

def create_db_with_table(db_path, table_name, columns):
    try:
        if os.path.exists(db_path):
            return
        db = sqlite3.connect(db_path)
        db_cursor_obj = db.cursor()
        db_cursor_obj.execute('CREATE TABLE "%s"(%s)' % (table_name, columns))
    except Exception as e:
        print("buba")
        # commit, close

def create_server_databases():
    for dictionary in SERVER_DATABASES_WITH_TABLES_AND_COLUMNS:
        create_db_with_table(dictionary["db_path"], dictionary["table_name"], dictionary["table_columns"])
# -------- Setup --------

# -------- Operations --------

def get_latest_data_from_db_by_table(db_path, table, data):
    db = sqlite3.connect(db_path)
    db_cursor_obj = db.cursor()
    output = db_cursor_obj.execute("SELECT %s FROM %s ORDER BY id DESC LIMIT 1" % (data, table)).fetchall()
    db_cursor_obj.close()
    return output

def get_all_data_from_table_column(db_path, table, column):
    db = sqlite3.connect(db_path)
    db_cursor_obj = db.cursor()
    output = db_cursor_obj.execute(
        "SELECT %s FROM %s ORDER BY id DESC" % (column, table)).fetchall()
    db_cursor_obj.close()
    return output

def get_all_data_from_table_row(db_path, table, condition_left, condition_right):
    db = sqlite3.connect(db_path)
    db_cursor_obj = db.cursor()
    output = db_cursor_obj.execute(
        "SELECT * FROM %s WHERE %s='%s' ORDER BY id DESC" % (table, condition_left, condition_right)).fetchall()
    db_cursor_obj.close()
    return output

def get_specific_data_from_table_row(db_path, table, string_columns_list):
    """string_columns_list example: "id, password, etc" """
    db = sqlite3.connect(db_path)
    db_cursor_obj = db.cursor()
    output = db_cursor_obj.execute(
        "SELECT %s FROM %s ORDER BY id DESC" % (string_columns_list, table)).fetchall()
    db_cursor_obj.close()
    return output

def get_specific_data_from_table_row_with_condition(db_path, table, string_columns_list, condition_left,
                                                    condition_right):
    """string_columns_list example: "id, password, etc" """
    db = sqlite3.connect(db_path)
    db_cursor_obj = db.cursor()
    output = db_cursor_obj.execute(
        "SELECT %s FROM %s WHERE %s=%s ORDER BY id DESC" % (
            string_columns_list, table, condition_left, condition_right)).fetchall()
    db.commit()
    db_cursor_obj.close()
    return output

def update_data_in_database(db_path, table_name, column, new_value, condition_left, condition_right):
    try:
        db = sqlite3.connect(db_path)
        db_cursor_obj = db.cursor()
        db_cursor_obj.execute('UPDATE "%s"'
                              'SET "%s"="%s"'
                              'WHERE "%s"="%s"'
                              % (table_name, column, new_value, condition_left, condition_right))
    except Exception as e:
        print("buba")
    finally:
        db.commit()
        db_cursor_obj.close()

def check_user_is_in_db(username):
    output = get_all_data_from_table_row(USERS_DB_NAME, USERS_DB_TABLE_NAME, "username", username)
    return(output)

def insert_user_into_db(username, password, rights = "user", password_reset = False):
    user_in_db = check_user_is_in_db(username)
    # Add username enumeration.
    if user_in_db:
        return{"User already registered. "}
    try:
        db = sqlite3.connect(USERS_DB_NAME)
        db_cursor_obj = db.cursor()
        db_cursor_obj.execute('INSERT INTO "{}" (username, password, rights, password_reset) values(?,?,?,?)'.format(USERS_DB_TABLE_NAME),
                                        (username, password, rights, password_reset))
    except Exception as e:
        print("buba")
        return{"Failed to register"}
    finally:
        db.commit()
        db_cursor_obj.close()
        return{"Registered successfully"}

def validate_user_with_password_in_db(username, password):
    # ToDo: Create a function that can evaluate 2 conditions at once ->> following code is not ok.
    dbUsername = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "username, password", "username", username)
    dbPassword = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "username, password", "password", password)
    if dbUsername[1] == dbPassword[1]:
        return True
    else:
        return False

def reset_password_status(username):
    try:
        trueOrFalse = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password_reset", "username", "'" + username + "'")
    except:
        trueOrFalse = False
    return(trueOrFalse)

def set_reset_password_to(username, resetPassword):
    # resetPassword is 1 or 0
    user_in_db = check_user_is_in_db(username)
    if not user_in_db:
        return("User not registered.")
    update_data_in_database(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password_reset", resetPassword, "username", username)
    return("Reset password successfully.")

def update_user_password(username, new_password):
    user_in_db = check_user_is_in_db(username)
    if not user_in_db:
        return("User not registered.")
    update_data_in_database(USERS_DB_NAME, USERS_DB_TABLE_NAME, "password", new_password, "username", username)
    return("Password updated successfully.")

def return_user_rights(username):
    rights_in_db = get_specific_data_from_table_row_with_condition(USERS_DB_NAME, USERS_DB_TABLE_NAME, "rights", "username", "'" + username + "'")
    return rights_in_db[0][0]

