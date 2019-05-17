# Copyright 2019 British Broadcasting Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from .models import db, User, OAuth2Client, AccessRights

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


def addAccessRights(user, IS04Access, IS05Access):
    access = AccessRights(user_id=user.id, is04=IS04Access, is05=IS05Access)
    add(access)
    return access


def addUser(username, password):
    user = User(username=username, password=password)
    add(user)
    return user

# -------------------- READ ------------------------- #
# from nmosauth.auth_server.db_utils import *


def printTables():
    for table in db.metadata.tables:
        print("Table: {}".format(table))


def printTable(table):
    return [i for i in table.query.all()]


def printTableString(table):
    return [str(i) for i in table.query.all()]


def printField(table, field):
    s = "[i." + field + " for i in table.query.all()]"
    return eval(s)


def getUser(user):
    if isinstance(user, int):
        entry = User.query.get_or_404(user)
    elif isinstance(user, str):
        entry = User.query.filter_by(username=user).first_or_404()
    return entry


def printForeign(table, key, val):  # Key is usually user_id
    s = "db.session.query(" + table + ").filter(" + table + "." + key + "==" + str(val) + ").all()"
    return eval(s)

# -------------------- UPDATE ------------------------- #


# DANGEROUS - DO NOT USE IN PRODUCTION. TESTING PURPOSES ONLY.
def updateField(table, find_field, find_value, change_field, change_value):
    entry = table + ".query.filter_by(" + find_field + "=str(" + find_value + ")).first()"
    entry = eval(entry)
    entry.change_field = change_value
    add(entry)
    return entry


# -------------------- DELETE ------------------------- #


def drop_all():
    db.session.remove()
    db.drop_all()


def remove(entry):
    db.session.delete(entry)
    db.session.commit()


def removeUser(user):
    if isinstance(user, int):
        entry = User.query.get_or_404(user)
    elif isinstance(user, str):
        entry = User.query.filter_by(username=user).first_or_404()
    remove(entry)


def removeClient(client_id):
    if isinstance(client_id, int):
        entry = OAuth2Client.query.get_or_404(client_id)
    else:
        entry = OAuth2Client.query.filter_by(client_id=client_id).first_or_404()
    remove(entry)


def removeAll(table):  # To clear token data
    for each in table.query.all():
        db.session.delete(each)
        remove(each)
