'''
This set of functions can be run from within
a "flask shell" to give app/database context '''

from .models import db, User, AccessRights

# -------------------- INIT ------------------------- #

# engine = db.engine
# inspector = db.inspect(engine)
# metadata = db.metadata(engine)


# Drop all tables and re-create
def clean_start():
    drop_all()
    create_all()

# -------------------- CREATE ------------------------- #


def create_all():
    db.create_all()
    # db.session.commit()


def add(entry):
    db.session.add(entry)
    db.session.commit()


def addAccessRights(IS04Access, IS05Access):
    entry = AccessRights(is_04_access=IS04Access, is_05_access=IS05Access)
    add(entry)


def addUser(username, password):
    entry = User(username=username, password=password)
    add(entry)


# -------------------- UPDATE ------------------------- #


def updateField(table, find_field, find_value, change_field, change_value):
    entry = "table.query.filter_by(" + find_field + "=str(" + find_value + ")).first()"
    entry = eval(entry)
    entry.change_field = change_value
    add(entry)
    return entry


# -------------------- REMOVE ------------------------- #


def drop_all():
    db.session.remove()
    db.drop_all()


def remove(entry):
    db.session.delete(entry)
    db.session.commit()


def removeUser(user):
    if isinstance(user, int):
        entry = User.query.get(id=user)
    elif isinstance(user, str):
        entry = User.query.filter_by(username=user).first()
    remove(entry)


def removeAll(table):  # To clear token data

    for each in table.query.all():
        db.session.delete(each)
        remove(each)


# -------------------- PRINT ------------------------- #
# from oauth2_server.db_utils import *

def printTables():
    for table in db.metadata.tables:
        print("Table: ", table)


def printTable(table):
    return [i for i in table.query.all()]


def printString(table):
    return [str(i) for i in table.query.all()]


def printField(table, field):
    s = "[i." + field + " for i in table.query.all()]"
    return eval(s)


def printUser(user):
    if isinstance(user, int):
        entry = User.query.get(user)
    elif isinstance(user, str):
        entry = User.query.filter_by(username=user).first()
    return entry


def printForeign(table, key, val):  # Key is usually user_id
    s = "db.session.query(table).filter(table." + key + "==" + str(val) + ").all()"
    return eval(s)
