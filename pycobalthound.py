#!/usr/bin/env python3

# So we can use the repo copy of pycobalt
import sys
import os
from netaddr.ip import cidr_merge
sys.path.insert(0, os.path.realpath(os.path.dirname(__file__)) + '/pycobalt')

# Importing the required regular libraries
import requests
import json
import pickle
import asyncio
import base64
import netaddr

from aiohttp import ClientSession
from requests.models import HTTPError
from requests.exceptions import ConnectionError

# Importing the required pycobalt libraries
import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.aggressor as aggressor
import pycobalt.gui as gui

# Importing the reporting functionality
from report import generate_report

# Cache settings (uses seperate caches to prevent issues when using multiple teamservers)
unique_id = (netaddr.IPAddress(aggressor.localip())).value
cache_location = os.path.realpath(os.path.dirname(__file__)) + '/cache/pycobalthound-' + str(unique_id) + '.cache'
settings_location = os.path.realpath(os.path.dirname(__file__)) + '/settings/pycobalthound-' + str(unique_id) + '.settings'
user_queries_location = os.path.realpath(os.path.dirname(__file__)) + '/queries/user-queries.json'
computer_queries_location = os.path.realpath(os.path.dirname(__file__)) + '/queries/computer-queries.json'
reportpath = ""

# Operator configurable settings (Neo4j connection + features)
# Check if settings have been saved
if os.path.isfile(settings_location):
    try:
        settings = pickle.load(open(settings_location, "rb"))
        engine.message('Restored settings from: ' + settings_location)
    except OSError:
            engine.debug("Could not load the settings file")

# If no settings were saved apply the defaults
else:
    settings = {
        "ignore_cache": False,
        "report": True,
        "notify": True,
        "notifytype": "pyNotify",
        "url": "http://localhost:7474/db/data/transaction/commit",
        "headers": { "Accept": "application/json; charset=UTF-8",
        "Content-Type": "application/json",
        "Authorization": "bmVvNGo6Ymxvb2Rob3VuZA=="
        }
    }

# Load user cypher queries
with open(user_queries_location, "r") as json_file:
    user_queries = json.load(json_file)

# Load computer cypher queries
with open(computer_queries_location, "r") as json_file:
    computer_queries = json.load(json_file)

# Check if Notify2 is installed
def check_notify2():
    try:
        import notify2
        return True
    except ImportError or ModuleNotFoundError:
        engine.error('Notify2 is not installed, falling back to native notifications!')
        settings["notifytype"] = "Native"
        return False
check_notify2()

engine.message(json.dumps(settings, indent=4))  
# Functions
# Cypher query functions
def do_sync_cypher(query):
    data = {"statements": [{'statement': query}]}
    response = ""
    
    try:
        response = requests.post(url=settings["url"],headers=settings['headers'],json=data)
        response.raise_for_status()
    except HTTPError as http_err:
        engine.error(f"An HTTP error has occurred: {http_err}")
    except ConnectionError as conn_err:
        engine.error(f"A connection error has occurred: Is the database online/reachable?")
    except Exception as err:
        engine.error(f"An error has ocurred: {err}")
    if response:
        return response

async def do_async_cypher(query, session):
    data = {"statements": [{'statement': query}]}
    try:
        response = await session.post(settings["url"], json=data)
        response.raise_for_status()
    except HTTPError as http_err:
        engine.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        engine.error(f"An error ocurred: {err}")
    result = await response.text()

    return result

async def do_async_query(query, accounts, session):
    result = {"name": [], "result": []}

    with_statement = make_with_statement(accounts)
    final_query = query["query"].format(statement=with_statement)
    
    try:
        response = await do_async_cypher(final_query, session)
        result["name"].append(query["name"])
        result["result"].append(response)
        return result
    except Exception as err:
        engine.error(f"Exception occured: {err}")
        pass

async def do_async_queries(queries, accounts):
    async with ClientSession(headers=settings["headers"]) as session:
        query_results = await asyncio.gather(*[do_async_query(query, accounts, session) for query in queries])
        return query_results

# Data handling/parsing functions
def check_valid_realm(credentials, domains):
    valid_users = []
    
    for x in credentials:
        if any(x["realm"].upper() in s for s in domains):
            valid_users.append(x)
    
    return valid_users

def check_cache(valid_users):
    keys = ['user', 'realm']
    
    parsed_users = []
    cached_users = []
    new_users = []
    
    if not settings['ignore_cache']:
        if not os.path.isdir(os.path.realpath(os.path.dirname(__file__)) + "/cache"):
            os.makedirs(os.path.realpath(os.path.dirname(__file__)) + "/cache")

    if not settings['ignore_cache']:
        try:
            cached_users = pickle.load(open(cache_location, "rb"))
            engine.debug('Restored users from: ' + cache_location)
        except OSError:
            engine.debug("Could not find a cache file")
    else:
        engine.message("Ignoring cache. If you want the benefit of caching you should enable the cache")

    for user in valid_users:
        parsed_users.append({key: user[key].upper() for key in keys})

    for user in parsed_users:
        if(user in cached_users):
            engine.debug("User was found in cache, skipping")
            continue
        else:
            if not settings['ignore_cache']:
                engine.debug("User was not found in cache, adding to cache and processing")
            cached_users.append(user)
            new_users.append(user)

    if not settings['ignore_cache']:
        cached_users = [user for user in cached_users if user in parsed_users]
        try:
            engine.debug("Saving the cache to: " + cache_location)
            pickle.dump(cached_users, open(cache_location, "wb"))
        except OSError:
            engine.error("Could not save cache!")

    return new_users

def check_user_type(new_users):
    transformed_users = new_users

    for user in transformed_users:
        if(user["user"][-1] == '$'):
            name = user["user"][:-1] + "." + user["realm"]
            user.update(type='Computer')
            user.update(username=name)
        else:
            name = user["user"] + "@" + user["realm"]
            user.update(type='User')
            user.update(username=name)

    return transformed_users

def get_domains():
    domains = []
    
    query = "MATCH (n:Domain) RETURN n"
    r = do_sync_cypher(query)
    j = json.loads(r.text)  
    for x in j["results"][0]["data"]:
        domains.append(x["row"][0]["name"])
    
    return domains

def make_with_statement(accounts):
    account_names = []

    for account in accounts:
        account_names.append(account["username"])
    query = f"WITH {account_names} AS samAccountNames UNWIND samAccountNames AS names"

    return query

def check_existence(transformed_users):
    existing_users = []
    
    with_statement = make_with_statement(transformed_users)
    query = f"{with_statement} MATCH (n) WHERE n.name STARTS with names RETURN n"
    r = do_sync_cypher(query)
    bh_json = json.loads(r.text)
    
    for transformed_user in transformed_users:
        for bh_user in bh_json["results"][0]["data"]:
            if transformed_user["username"].upper() in bh_user["row"][0]["name"].upper():
                existing_users.append({"username": bh_user["row"][0]["name"], "type": transformed_user["type"]})

    return existing_users

def mark_owned(existing_users):
    with_statement = make_with_statement(existing_users)
    query = f"{with_statement} MATCH (n) WHERE n.name STARTS with names SET n.owned = TRUE"
    do_sync_cypher(query)

def parse_results(queries, results):
    parsed_results = []

    for query in queries:
        data = []
        result = next((result for result in results if ("".join(result['name'])) == query['name']), None)
        entries = json.loads(result['result'][0])
        for entry in entries['results'][0]['data']:
            data.append("".join(entry['row']))

        parsed_results.append({'name': query['name'], 'report': query['report'], 'result': data})
    return parsed_results

def notify(header, message):
    if settings["notifytype"] == "pyNotify" and check_notify2:
        import notify2
        notify2.init("pyCobaltHound")
        u = notify2.Notification(header, message)
        u.set_timeout(300000)
        u.show()
    else:
        aggressor.show_message(message)

def notify_operator(user_results, computer_results, reportpath):
    if all(len(result['result']) == 0 for result in user_results) == False:
        message = ""
        for result in user_results:
            if len(result['result']) != 0:
                message = message + result['report'].format(number=len(result['result'])) + "\n"
            
        if reportpath:
            message = message + "\n" + "More details can be found in: " + reportpath + "\n"
        notify("pyCobalthound - User report", message[:-1])

    if all(len(result['result']) == 0 for result in computer_results) == False:
        message = ""
        for result in computer_results:
            if len(result['result']) != 0:
                message = message + result['report'].format(number=len(result['result'])) + "\n"
        if reportpath:
            message = message + "\n" + "More details can be found in: " + reportpath + "\n"
        notify("pyCobaltHound - Computer report", message[:-1])


# Neo4j connection test
def connection_test():
    query = "MATCH (n:Domain) RETURN n"
    r = do_sync_cypher(query)
    
    if r:
        j = json.loads(r.text)
        if r.status_code != requests.codes.ok:
            if r.status_code in('400', '401'):
                engine.error("Neo4j connection failed: " + j["errors"][0]["message"])
                return False
            else:
                engine.error("Neo4j connection failed: unspecified failure")
                engine.error(r.text)
                return False
        else:
            engine.message("Neo4j connection succeeded")
            return True
    else:
        return False

def connection_test_wrapper():
    if connection_test():
        return True
    else:
        aggressor.show_error("Could not connect to Neo4j, check your credentials and URL")
        return False

# Main parsing and query logic
def credential_action(credentials, event=True, report=True):
    reportpath = ""
    if connection_test_wrapper():
        # Transforming data and checking validity
        domains = get_domains()
        valid_users = check_valid_realm(credentials, domains)
        if event:
            new_users = check_cache(valid_users)
        else:
            new_users = valid_users
        transformed_users = check_user_type(new_users)
        
         # Checking if the accounts exists in BloodHound
        existing_users = check_existence(transformed_users)
        
        if existing_users:
            # Marking the existing accounts as owned
            if event:
                mark_owned(existing_users)

            # Separate user and computer accounts
            user_accounts = [user for user in existing_users if user["type"] == "User"]
            computer_accounts = [user for user in existing_users if user["type"] == "Computer"]
            
            # Get enabled queries
            enabled_user_queries = [query for query in user_queries if query["enabled"] == "True"]
            enabled_computer_queries = [query for query in computer_queries if query["enabled"] == "True"]

            # Perform queries
            user_queries_results = asyncio.run(do_async_queries(enabled_user_queries, user_accounts))
            computer_queries_results = asyncio.run(do_async_queries(enabled_computer_queries, computer_accounts))

            # Parse results
            user_results = parse_results(enabled_user_queries, user_queries_results)
            computer_results = parse_results(enabled_computer_queries, computer_queries_results)
            
            # Report results
            if report:
                if settings['report']:
                    reportpath = generate_report(user_results, computer_results)
            if settings['notify']:
                notify_operator(user_results, computer_results, reportpath)

# Test Neo4j connection on load
connection_test_wrapper()

# define aggressor menu and callbacks
# wipe cache menu
def wipe_cache(values):  
    if os.path.exists(cache_location):
        os.remove(cache_location)
        aggressor.show_message("Cache wiped!")
    else:
        aggressor.show_error("No cache found")

def wipe_cache_dialog():
    aggressor.prompt_confirm("Are you sure you want to wipe the cache? If you do so, pyCobaltHound will query every compromised user again upon its next run", "Wipe cache", wipe_cache)

# recalculate menu
def recalculate():
    aggressor.fireEvent('credentials', aggressor.credentials())

# settings menu
def aggressor_empty_callback():
    engine.debug('')

def update_settings(dialog, button_name, values):
    global settings
    auth = (base64.b64encode((values["username"] + ":" + values["password"]).encode('ascii'))).decode('utf-8')
    settings['headers']['Authorization'] = auth

    settings['url'] = values["url"] + '/db/data/transaction/commit'
    
    if values["cachecheck"] == 'Disabled':
        settings["ignore_cache"] = True
    else:
        settings["ignore_cache"] = False

    if values["notificationcheck"] == 'Enabled':
        settings["notify"] = True
    else:
        settings["notify"] = False

    if values["reportcheck"] == "Enabled":
        settings["report"] = True
    else:
        settings["report"] = False

    if values["notifytype"] == "pyNotify" and check_notify2:
        settings["notifytype"] = "pyNotify"
    else:
        settings["notifytype"] = "Native"

    if values['persistent'] == 'Yes':
        if not os.path.isdir(os.path.realpath(os.path.dirname(__file__)) + "/settings"):
            os.makedirs(os.path.realpath(os.path.dirname(__file__)) + "/settings")
        try:
            engine.debug("Saving the settings to: " + settings_location)
            pickle.dump(settings, open(settings_location, "wb"))
        except OSError:
            engine.error("Could not save cache!")
    ## Test new settings (TODO: Make check blocking for update if creds are wrong)
    connection_test_wrapper()

def update_settings_dialog():
    global settings
    drows = {
        'username': 'neo4j',
		'password': 'bloodhound',        
    }

    drows["url"] = settings["url"][:-27]
    drows["persistent"] = "Yes"
    drows["notifytype"] = settings["notifytype"]

    # Overkill just because I want nice menus :D
    if settings["ignore_cache"]:
        drows["cachecheck"] = "Disabled"
    else:
        drows["cachecheck"] = "Enabled"

    if settings["notify"]:
        drows["notificationcheck"] = "Enabled"
    else:
        drows["notificationcheck"] = "Disabled"

    if settings["report"]:
        drows["reportcheck"] = "Enabled"
    else:
        drows["reportcheck"] = "Disabled"
    
    dialog = aggressor.dialog("pyCobaltHound settings", drows, update_settings)
    aggressor.dialog_description(dialog, "Update your pyCobaltHound settings")
    aggressor.drow_text(dialog, "username", "Neo4j username:  ")
    aggressor.drow_text(dialog, "password", "Neo4j password: ")
    aggressor.drow_text(dialog, "url", "Neo4j URL (http://server:port)")
    aggressor.drow_combobox(dialog, "cachecheck", "Caching", ["Enabled", "Disabled"])
    aggressor.drow_combobox(dialog, "notificationcheck", "Notifications", ["Enabled", "Disabled"])
    aggressor.drow_combobox(dialog, "notifytype", "Notification method", ["Native", "pyNotify"])
    aggressor.drow_combobox(dialog, "reportcheck", "Reporting", ["Enabled", "Disabled"])
    aggressor.drow_combobox(dialog, "persistent", "Save settings persistently", ["Yes", "No"])
    aggressor.dbutton_action(dialog, "Update")
    aggressor.dialog_show(dialog)

# query updating menu
def update_queries(dialog, button_name, values):
    global user_queries
    global computer_queries

    if values["type"] == "User":
        engine.message("Updating user queries")
        queries = user_queries
        query_location = user_queries_location
        
        for query in queries:
            if values[query["name"]] == "Enabled":
                query["enabled"] = "True"

            else:
                query["enabled"] = "False"

        user_queries = queries

        if values["persistent"] == "Yes":
            with open(query_location, "w") as json_file:
                json.dump(user_queries, json_file, indent=4)
    else:
        engine.message("Updating computer queries")
        queries = computer_queries
        query_location = computer_queries_location  
        
        for query in queries:
            if values[query["name"]] == "Enabled":
                query["enabled"] = "True"

            else:
                query["enabled"] = "False"
        
        computer_queries = queries

        if values["persistent"] == "Yes":
            with open(query_location, "w") as json_file:
                json.dump(user_queries, json_file, indent=4)


def update_queries_dialog(dialog, button_name, values):
    predrows = []
    drows = {}

    if values["type"] == "User":
        queries = user_queries
    else:
        queries = computer_queries

    for query in queries:
        dict = {"name": query["name"], "enabled": query["enabled"]}
        predrows.append(dict)
    
    for predrow in predrows:
        # Overkill just because I want nice menus :D
        if predrow["enabled"] == "True":
            state = "Enabled"
            opposite = "Disabled"
        else:
            state = "Disabled"
            opposite = "Enabled"
        
        drows[predrow["name"]] = state

    dialog = aggressor.dialog("Query selection", drows, update_queries)
    for drow in drows:
        
        aggressor.drow_combobox(dialog, drow, drow, ["Enabled", "Disabled"])
    
    drows["persistent"] = "Yes"
    drows["type"] = values["type"]
    aggressor.drow_combobox(dialog, "persistent", "Save settings persistently", ["Yes", "No"])
    # Ugly hack to pass query type to the next function
    aggressor.drow_combobox(dialog, "type", "Query type", [values["type"]])
    aggressor.dbutton_action(dialog, "Update")
    aggressor.dialog_show(dialog)

def update_queries_choice_dialog():
    drows = {
        'type': "User"
    }

    dialog = aggressor.dialog("Query selection", drows, update_queries_dialog)
    aggressor.dialog_description(dialog, "Which type of query do you want to update?")
    aggressor.drow_combobox(dialog, "type", "Query  type", ["User", "Computer"])
    aggressor.dbutton_action(dialog, "Choose")
    aggressor.dialog_show(dialog)

# add query menu
def add_query(dialog, button_name, values):
    global user_queries
    global computer_queries
    
    if values["enabled"] == "Enabled":
        state = "True"
    else:
        state = "False"

    new_query = {
        "name": values["name"],
        "statement": values["statement"],
        "report": values["report"],
        "enabled": state,
        "custom": "True"
    }

    if values["type"] == "User":
        user_queries.append(new_query)
        if values["persistent"] == "Yes":
            with open(user_queries_location, "w") as json_file:
                json.dump(user_queries, json_file, indent=4)
    
    if values["type"] == "Computer":
        computer_queries.append(new_query)
        if values["persistent"] == "Yes":
            with open(computer_queries_location, "w") as json_file:
                json.dump(computer_queries, json_file, indent=4)

def add_query_dialog():
    drows = {
        "name": "name of your query",
        "statement": "{statement} ... RETURN DISTINCT(x.name)",
        "report": "{number} entity(s) has/have a path to target.",
        "enabled": "Enabled",
        "type": "User",
        "persistent": "Yes"
    }

    dialog = aggressor.dialog("Add a custom query", drows, add_query)
    aggressor.dialog_description(dialog, "Fill in the required information")
    aggressor.drow_text(dialog, "name", "Name")
    aggressor.drow_text_big(dialog, "statement", "Cypher query")
    aggressor.drow_text(dialog, "report", "Report headline")
    aggressor.drow_combobox(dialog, "enabled", "Status", ["Enabled", "Disabled"])
    aggressor.drow_combobox(dialog, "type", "Query type", ["User", "Computer"])
    aggressor.drow_combobox(dialog, "persistent", "Save query persistently", ["Yes", "No"])
    aggressor.dbutton_action(dialog, "Add")
    aggressor.dialog_show(dialog)

# remove query menu
def remove_query(dialog, button_name, values):
    global user_queries
    global computer_queries

    if values["type"] == "User":
        user_queries = [query for query in user_queries if not (query["custom"] == "True" and values[query["name"]] == "Delete")]
        if values["persistent"] == "Yes":
            with open(user_queries_location, "w") as json_file:
                json.dump(user_queries, json_file, indent=4)

    if values["type"] == "Computer":
        computer_queries = [query for query in computer_queries if not (query["custom"] == "True" and values[query["name"]] == "Delete")]
        if values["persistent"] == "Yes":
            with open(computer_queries_location, "w") as json_file:
                json.dump(computer_queries, json_file, indent=4)

def remove_query_dialog(dialog, button_name, values):
    drows = {}
    custom_query_exists = False

    if values["type"] == "User":
        queries = user_queries
    else:
        queries = computer_queries
    
    # check if there is a custom query defined
    for query in queries:
        if query["custom"] == "True":
            custom_query_exists = True
    
    if custom_query_exists:
        dialog = aggressor.dialog("Remove a custom query", drows, remove_query)
        aggressor.dialog_description(dialog, "Which query do you want to remove?")
        for query in queries:
            if query["custom"] == "True":
                drows[query["name"]] = "Keep"
                aggressor.drow_combobox(dialog, query["name"], query["name"], ["Keep", "Delete"])
        drows["persistent"] = "Yes"
        drows["type"] = values["type"]
        aggressor.drow_combobox(dialog, "persistent", "Delete query permanently", ["Yes", "No"])
        # Ugly hack to pass query type to the next function
        aggressor.drow_combobox(dialog, "type", "Query type", [values["type"]])
        aggressor.dbutton_action(dialog, "Delete")
        aggressor.dialog_show(dialog)
    else:
        aggressor.show_error("There are no custom " + values["type"].lower() + " queries to delete!")

def remove_query_choice_dialog():
    drows = {
        'type': "User"
    }

    dialog = aggressor.dialog("Query selection", drows, remove_query_dialog)
    aggressor.dialog_description(dialog, "Which type of query do you want to remove?")
    aggressor.drow_combobox(dialog, "type", "Query  type", ["User", "Computer"])
    aggressor.dbutton_action(dialog, "Choose")
    aggressor.dialog_show(dialog)


# menu layout    
menu = gui.popup("aggressor", callback=aggressor_empty_callback, children=[
    gui.menu("pyCobaltHound", children=[
        gui.insert_menu('pyCobaltHound_top'),
        gui.item("Settings", callback=update_settings_dialog),
        gui.menu("Queries", children=[
            gui.item("Update queries", callback=update_queries_choice_dialog),
            gui.item("Add query", callback=add_query_dialog),
            gui.item("Remove query", callback=remove_query_choice_dialog)
        ]),
        gui.item("Wipe cache", callback=wipe_cache_dialog),
        gui.item("Recalculate", callback=recalculate)
    ])
])

#  define credentials menu and callbacks
def credentials_empty_callback(values):
    engine.debug('')

def update_cache_callback(values):
    keys = ['user', 'realm']
    parsed_users = []
    try:
        cached_users = pickle.load(open(cache_location, "rb"))
        engine.debug('Restored users from: ' + cache_location)
    except OSError:
        engine.debug("Could not find a cache file")

    if cached_users:
        for user in values:
            parsed_users.append({key: user[key].upper() for key in keys})

        new_cached_users = [user for user in cached_users if not (user in parsed_users)]
        try:
            engine.debug("Saving the cache to: " + cache_location)
            pickle.dump(new_cached_users, open(cache_location, "wb"))
        except OSError:
            engine.error("Could not save cache!")

credential_menu = gui.popup('credentials', callback=credentials_empty_callback, children=[
    gui.menu('pyCobaltHound', children=[
        gui.insert_menu('pyCobaltHound_top'),
        gui.item("Remove from cache", callback=update_cache_callback),
    ])
])

# define beacons menu and callbacks
def beacons_empty_callback(values):
    engine.debug('')

def investigate_action(dialog, button_name, values):
    beacons = aggressor.beacons()
    target_beacons = values["beacons"]
    targets = []
    for beacon in beacons:
        user = ""
        computer = ""
        if (beacon["id"] in target_beacons):
            user = beacon["user"]
            computer = beacon["computer"]
            
            # Check if beacon is running as LA or SYSTEM
            if user == "SYSTEM *":
                system = True
            # This will exclude the "Administrator" DA in AD too, but I guess you don't need to investigate if you've got a high integrity beacon as that :)
            elif user == "Administrator *":
                system == True
            else:
                system = False

            # Format user/computer names
            if user[-1] == "*":
                user = user[:-2].upper()
            else:
                user = user.upper()
            
            computer = computer.upper() + "$"

            # Add to list of objects to be marked
            if values["investigate"] == "Both":
                if system:
                    targets.append({'user': computer, 'realm': values["domain"]})
                else:
                    targets.append({'user': user, 'realm': values["domain"]})
                    targets.append({'user': computer, 'realm': values["domain"]})
            if values["investigate"] == "User":
                targets.append({'user': user, 'realm': values["domain"]})
            if values["investigate"] == "Computer":
                targets.append({'user': computer, 'realm': values["domain"]})
    
    engine.message(values["report"])
    credential_action(targets, False)

def investigate_dialog(values):
    drows = {
        "beacons": values,
        "investigate": "Both",
        "domain": "CONTOSO.LOCAL",
        "report": "false"
    }

    investigate = ['Both', 'User', 'Computer']
    domains = get_domains()

    dialog = aggressor.dialog("Investigate", drows, investigate_action)
    aggressor.dialog_description(dialog, "Investigate users & computers")
    aggressor.drow_combobox(dialog, "investigate", "Investigate", investigate)
    aggressor.drow_combobox(dialog, "domain", 'Domain', domains)
    aggressor.drow_checkbox(dialog, "report", "Generate a report")
    aggressor.dbutton_action(dialog, "Investigate")
    aggressor.dialog_show(dialog)

def mark_owned_action(dialog, button_name, values):
    beacons = aggressor.beacons()
    owned_beacons = values["beacons"]
    targets = []
    for beacon in beacons:
        user = ""
        computer = ""
        if (beacon["id"] in owned_beacons):
            
            user = beacon["user"]
            computer = beacon["computer"]

            # Cobalt Strike shows high integrity beacons as "User *"
            if user[-1] == "*":
                admin = True
            else:
                admin = False
            # Check if beacon is running as LA or SYSTEM
            if user == "SYSTEM *":
                system = True
            elif user == "Administrator *":
                system == True
            else:
                system = False
            # Format user/computer names
            if user[-1] == "*":
                user = user[:-2].upper()
            else:
                user = user.upper()
            
            computer = computer.upper() + "$"

            # Add to list of objects to be marked
            if values["nodetype"] == "Default":
                if system:
                    targets.append({'user': computer, 'realm': values["domain"]})
                elif admin:
                    targets.append({'user': user, 'realm': values["domain"]})
                    targets.append({'user': computer, 'realm': values["domain"]})
                else:
                    targets.append({'user': user, 'realm': values["domain"]})
            if values["nodetype"] == "User":
                    targets.append({'user': user, 'realm': values["domain"]})
            if values["nodetype"] == "Computer":
                targets.append({'user': computer, 'realm': values["domain"]})

    # Mark targets as owned                
    transformed_users = check_user_type(targets)
    existing_users = check_existence(transformed_users)
    if existing_users:
        mark_owned(existing_users)

def mark_owned_dialog(values):
    drows = {
        "beacons": values,
        "nodetype": "Default",
        "domain": "CONTOSO.LOCAL"
    }

    nodetypes = ['Default', 'User', 'Computer']
    domains = get_domains()

    dialog = aggressor.dialog("Mark as owned", drows, mark_owned_action)
    aggressor.dialog_description(dialog, "Mark beacons as owned")
    aggressor.drow_combobox(dialog, "nodetype", "Nodetype", nodetypes)
    aggressor.drow_combobox(dialog, "domain", 'Domain', domains)
    aggressor.dbutton_action(dialog, "Mark")
    aggressor.dialog_show(dialog)

beacon_menu = gui.popup('beacon', callback=beacons_empty_callback, children=[
    gui.menu('pyCobaltHound', children=[
        gui.insert_menu('pyCobaltHound_top'),
        gui.item("Mark as owned", callback=mark_owned_dialog),
        gui.item("Investigate", callback=investigate_dialog)
    ])
])

# register menus
gui.register(menu)
gui.register(credential_menu)
gui.register(beacon_menu)

def test():
    engine.message(test)

# Reacting to the "on credentials" event in Cobalt Strike
@events.event('credentials')
def credential_action_wrapper(credentials):
    credential_action(credentials)

# Read commands from cobaltstrike. must be called last
engine.loop()

