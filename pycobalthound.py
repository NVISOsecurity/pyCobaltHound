#!/usr/bin/env python3

# So we can use the repo copy of pycobalt
import sys
import os
sys.path.insert(0, os.path.realpath(os.path.dirname(__file__)) + '/pycobalt')

# Importing the required regular libraries
import requests
import json
import pickle
import ctypes
import asyncio
import notify2
import base64

from aiohttp import ClientSession
from requests.models import HTTPError
from requests.exceptions import ConnectionError

# Importing the required pycobalt libraries
import pycobalt.engine as engine
import pycobalt.events as events
import pycobalt.aggressor as aggressor
import pycobalt.gui as gui

# Importing the HTML reporting functionality
from report import generate_report

# Cache settings (uses seperate caches to prevent issues when using multiple teamservers)
unique_id = (ctypes.c_size_t(hash(aggressor.localip())).value)
cache_location = os.path.realpath(os.path.dirname(__file__)) + '/pycobalthound-' + str(unique_id) + '.cache'
ignore_cache = False

# Report & notification settings 
report = True # (to do, make operator configurable..)
reportpath = ""
notify = True

# Neo4j connection settings (to do, make operator configurable..)
url = 'http://localhost:7474/db/data/transaction/commit'
auth = "bmVvNGo6Ymxvb2Rob3VuZA=="
headers = { "Accept": "application/json; charset=UTF-8",
        "Content-Type": "application/json",
    "Authorization": auth }

# User cypher queries
user_queries = [
    {
        "name": "path_to_hvt",
        "query" : "{statement} MATCH (u:User) WHERE u.name STARTS WITH names MATCH (n {{highvalue:true}}),p=shortestPath((u)-[r*1..]->(n)) WHERE NONE (r IN relationships(p) WHERE type(r)= 'GetChanges') AND NONE (r in relationships(p) WHERE type(r)='GetChangesAll') AND NOT n.objectid ENDS WITH '-512' AND NOT u=n RETURN DISTINCT(u.name)",
        "report" : "{number} user(s) has/have a path to a high value target."
    },
    {
        "name": "path_to_da",
        "query" : "{statement} MATCH (u:User) WHERE u.name STARTS WITH names MATCH p=shortestPath((u)-[:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin|ReadGMSAPassword|HasSIDHistory|CanPSRemote|AZAddMembers|AZContains|AZContributor|AZGetCertificates|AZGetKeys|AZGetSecrets|AZGlobalAdmin|AZOwns|AZPrivilegedRoleAdmin|AZResetPassword|AZUserAccessAdministrator|AZAppAdmin|AZCloudAppAdmin|AZRunsAs|AZKeyVaultContributor*1..]->(m:Group)) WHERE m.objectid ENDS WITH '-512' AND NOT u=m RETURN DISTINCT(u.name)",
        "report" : "{number} user(s) has/have a path to domain admins."
    },
    {
        "name": "test empty query",
        "query" : "{statement} MATCH (u:User) WHERE u.name STARTS WITH names AND u.objectid ENDS WITH '-499' RETURN u",
        "report" : "this is just to test a query with empty result set"
    }
]

# Computer cypher queries
computer_queries = [
    {
        "name": "path_to_hvt",
        "query" : "{statement} MATCH (u:Computer) WHERE u.name STARTS WITH names MATCH (n {{highvalue:true}}),p=shortestPath((u)-[r*1..]->(n)) WHERE NONE (r IN relationships(p) WHERE type(r)= 'GetChanges') AND NONE (r in relationships(p) WHERE type(r)='GetChangesAll') AND NOT n.objectid ENDS WITH '-512' AND NOT u=n RETURN DISTINCT(u.name)",
        "report" : "{number} computer(s) has/have a path to a high value target."
    }
]

# Functions
# Cypher query functions
def do_sync_cypher(query):
    data = {"statements": [{'statement': query}]}
    response = ""
    
    try:
        response = requests.post(url=url,headers=headers,json=data)
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
        response = await session.post(url, json=data)
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
    async with ClientSession(headers=headers) as session:
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
    
    if not ignore_cache:
        try:
            cached_users = pickle.load(open(cache_location, "rb"))
            engine.message('Restored users from: ' + cache_location)
        except OSError:
            engine.message("Could not find a cache file")
    else:
        engine.message("Ignoring cache. If you want the benefit of caching you should enable the cache")

    for user in valid_users:
        parsed_users.append({key: user[key].upper() for key in keys})

    for user in parsed_users:
        if(user in cached_users):
            engine.message("User was found in cache, skipping")
            continue
        else:
            if not ignore_cache:
                engine.message("User was not found in cache, adding to cache and processing")
            cached_users.append(user)
            new_users.append(user)

    if not ignore_cache:
        cached_users = [user for user in cached_users if user in parsed_users]
        try:
            engine.message("Saving the cache to: " + cache_location)
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

def notify_operator(user_results, computer_results, reportpath):
    notify2.init("pyCobaltHound")
    if all(len(result['result']) == 0 for result in user_results) == False:
        message = ""
        for result in user_results:
            if len(result['result']) != 0:
                message = message + result['report'].format(number=len(result['result'])) + '\n'
        
        u = notify2.Notification("pyCobalthound - User report", message[:-1])
        u.set_timeout(300000)
        u.show()

    if all(len(result['result']) == 0 for result in computer_results) == False:
        message = ""
        for result in computer_results:
            if len(result['result']) != 0:
                message = message + result['report'].format(number=len(result['result'])) + '\n'
        
        c = notify2.Notification("pyCobaltHound - Computer report", message[:-1])
        c.set_timeout(30000)
        c.show()

    if reportpath:
        message = "More details can be found in: " + reportpath
        c = notify2.Notification("pyCobaltHound - Report generated", message)
        c.set_timeout(30000)
        c.show()

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

# register menu's and callbacks
def wipe_cache(values):  
    if os.path.exists(cache_location):
        os.remove(cache_location)
        aggressor.show_message("Cache wiped!")
    else:
        aggressor.show_error("No cache found")

def wipe_cache_dialog():
    aggressor.prompt_confirm("Are you sure you want to wipe the cache? If you do so, pyCobaltHound will query every compromised user again upon its next run", "Wipe cache", wipe_cache)

def aggressor_empty_callback():
    engine.debug('')

def update_settings(dialog, button_name, values):
    engine.message(values)

    global ignore_cache
    global report
    global url
    global notify
    global auth
    global headers

    username = values["username"]
    password = values["password"]
    auth = (base64.b64encode((username + ":" + password).encode('ascii'))).decode('utf-8')
    headers = { "Accept": "application/json; charset=UTF-8",
        "Content-Type": "application/json",
    "Authorization": auth }
    url = values["url"] + '/db/data/transaction/commit'
    
    if values["cachecheck"] == 'false':
        ignore_cache = True
    else:
        ignore_cache = False

    if values["notificationcheck"] == 'false':
        notify = False
    else:
        notify = True

    if values["reportcheck"] == "false":
        report = False
    else:
        report = True

    connection_test_wrapper()

def update_settings_dialog():
    drows = {
        'username': 'neo4j',
		'password': 'bloodhound',
		'url' : 'http://localhost:7474',
		'ignore_cache' : "true",
		'report' : "true",
		'notify' : "true"
    }

    dialog = aggressor.dialog("pyCobaltHound settings", drows, update_settings)
    aggressor.dialog_description(dialog, "Update your pyCobaltHound settings")
    aggressor.drow_text(dialog, "username", "Neo4j username:  ")
    aggressor.drow_text(dialog, "password", "Neo4j password: ")
    aggressor.drow_text(dialog, "url", "Neo4j URL")
    aggressor.drow_checkbox(dialog, "cachecheck", "Enable cache")
    aggressor.drow_checkbox(dialog, "notificationcheck", "Enable notifications")
    aggressor.drow_checkbox(dialog, "reportcheck", "Enable reporting")
    aggressor.dbutton_action(dialog, "Update")
    aggressor.dialog_show(dialog)

menu = gui.popup('aggressor', callback=aggressor_empty_callback, children=[
    gui.menu('pyCobaltHound', children=[
        gui.insert_menu('pyCobaltHound_top'),
        gui.item("Settings", callback=update_settings_dialog),
        gui.separator(),
        gui.item("Wipe cache", callback=wipe_cache_dialog)
    ])
])

gui.register(menu)

# test event (remove)

@events.event('update-check', official_only=False)
def check():
    engine.message("ignore: " + str(ignore_cache))
    engine.message("report: " + str(report))
    engine.message("url: " + url)
    engine.message("notify: " + str(notify))
    engine.message("auth: " + auth)

# Reacting to the "on credentials" event in Cobalt Strike
@events.event('credentials')
def credential_action(credentials):
    if connection_test_wrapper():
        # Transforming data and checking validity
        domains = get_domains()
        valid_users = check_valid_realm(credentials, domains)
        new_users = check_cache(valid_users)
        transformed_users = check_user_type(new_users)
        
        # Checking if the accounts exists in BloodHound
        existing_users = check_existence(transformed_users)
        
        # Marking the existing accounts as owned
        mark_owned(existing_users)

        # Separate user and computer accounts
        user_accounts = [user for user in existing_users if user["type"] == "User"]
        computer_accounts = [user for user in existing_users if user["type"] == "Computer"]

        # Perform queries
        user_queries_results = asyncio.run(do_async_queries(user_queries, user_accounts))
        computer_queries_results = asyncio.run(do_async_queries(computer_queries, computer_accounts))

        # Parse results
        user_results = parse_results(user_queries, user_queries_results)
        computer_results = parse_results(computer_queries, computer_queries_results)
        
        # Report results
        if report:
            reportpath = generate_report(user_results, computer_results)
        if notify:
            notify_operator(user_results, computer_results, reportpath)

# Test Neo4j connection on load
connection_test_wrapper()
# Read commands from cobaltstrike. must be called last
engine.loop()

