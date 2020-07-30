from pyaml import yaml
import os
import csv
import datetime
import logging
from gib_ti.gib_ti.APIClient import APIClient
from pprint import pprint

collections_fields = {
    "compromised/account": ["dateCompromised", "dateDetected", "client/ipv4/ip", "login", "password", "domain","cnc/ipv4/ip", "cnc/cnc"],
    "compromised/card": ["dateCompromised", "dateDetected", "cardInfo/number", "owner/name", "owner/city", "owner/email", "cnc/cnc", "cnc/ipv4/ip"],
    "compromised/mule": ["dateAdd", "dateIncident", "account", "cnc/cnc", "cnc/domain", "cnc/ipv4/ip", "organization/name", "person/name", "person/email", "person/phone", "threatActor/name"],
    "compromised/imei": ["dateDetected", "dateCompromised", "device/imei", "device/model", "cnc/cnc", "cnc/ipv4/ip"],
    "compromised/file": ["dateCompromised", "dateDetected", "fileInfo/filename", "fileInfo/md5", "malware/name", "threatActor/name", "cnc/cnc", "cnc/ipv4/ip"],
    "attacks/ddos": ["dateReg", "dateBegin", "dateEnd", "target/ipv4/ip", "target/domain", "target/url", "cnc/cnc", "cnc/ipv4/ip"],
    "attacks/deface": ["date", "targetDomain", "targetIp/ip", "threatActor/name", "url"],
    "attacks/phishing": ["dateDetected", "dateBlocked", "ipv4/ip", "phishingDomain/domain", "phishingDomain/dateRegistered", "phishingDomain/title"],
    "attacks/phishing_kit": ["hash", "downloadedFrom/url", "downloadedFrom/domain", "emails", "targetBrand"],
    "bp/phishing": ["dateDetected", "dateBlocked", "ipv4/ip", "phishingDomain/domain", "phishingDomain/dateRegistered", "phishingDomain/title"],
    "bp/phishing_kit": ["hash", "downloadedFrom/url", "downloadedFrom/domain", "emails", "targetBrand"],
    "hi/threat": ["id", "dateFirstSeen", "dateLastSeen", "datePublished", "threatActor/name", "indicators/params/ipv4", "indicators/params/hashes/md5", "indicators/params/hashes/sha1", "indicators/params/hashes/sha256"],
    "hi/threat_actor": ["createdAt", "name", "aliases", "labels", "langs"],
    "apt/threat": ["id", "dateFirstSeen", "dateLastSeen", "datePublished", "threatActor/name", "indicators/params/ipv4", "indicators/params/hashes/md5", "indicators/params/hashes/sha1", "indicators/params/hashes/sha256"],
    "apt/threat_actor": ["createdAt", "name", "aliases", "labels", "langs"],
    "osi/git_leak": ["dateDetected", "name", "repository", "matchesType", "revisions/info/authorEmail", "revisions/info/authorName", "revisions/info/dateDetected"],
    "osi/public_leak": ["datePublished", "created", "hash", "size", "matchType", "keyword", "link"],
    "osi/vulnerability": ["datePublished","id", "cvss/score", "description", "reporter", "software/softwareName", "software/softwareVersionString", "software/vendor"],
    "malware/cnc": ["dateDetected", "dateLastSeen", "cnc", "ipv4/ip", "domain", "threatActor/name", "malwareList/name", "platform"],
    "malware/malware": ["name", "platform", "shortDescription", "threatLevel"],
    "malware/targeted_malware": ["date", "malware/name", "md5", "injectMd5", "threatActor/name", "fileName", "fileType", "size", "source" ],
    "suspicious_ip/tor_node": ["dateFirstSeen", "dateLastSeen", "ipv4/ip", "source"],
    "suspicious_ip/open_proxy": ["dateDetected", "dateFirstSeen", "ipv4/ip", "type", "port", "source"],
    "suspicious_ip/socks_proxy": ["dateDetected", "dateFirstSeen", "ipv4/ip", "source"]
}


additional_fields = {
    "apt/threat/mitre_matrix": ["threat/id", "threatActor/name", "title", "attackTactic", "attackType", "tacticId"],
    "hi/threat/mitre_matrix": ["threat/id", "threatActor/name", "title", "attackTactic", "attackType", "tacticId"]
}


with open("configuration.yml", "r") as configuration_file:
    config = yaml.safe_load(configuration_file)

API_URL = config["client"]["api_url"] if config["client"]["api_url"][-1] == "/" else config["client"]["api_url"] + "/"
API_USERNAME = config["client"]["username"]
API_KEY = config["client"]["api_key"]
BIG_DATA_COLLECTIONS = ["hi/threat", "apt/threat"]
LIMIT = config["client"]["default_limit"]
BIG_DATA_LIMIT = config["client"]["big_data_limit"]
CONFIG_FILE = "configuration.yml"
DATA_DIR = config["client"]["data_dir"]

PROXY_PROTOCOL = config["proxy"]["protocol"]
PROXY_ADDRESS = config["proxy"]["ip_addr"]
PROXY_PORT = config["proxy"]["port"]
PROXY_USERNAME = config["proxy"]["username"]
PROXY_PASSWORD = config["proxy"]["password"]



def find_attrs(sample, attrs):
    """Find attrs in json (won't work with lists), sep by '/'
    Args:
        sample: jsoned python dict
        attrs: list of attrs strings

    Returns:

    """
    def find_attr(s, attr):
        attr = attr.split("/", 1)
        if len(attr) == 1: 
            if isinstance(s, type(None)) or s == []:
                return None
            else:
                return s.get(attr[0])
        else:
            return find_attr(s.get(attr[0]), attr[1])

    ret = [find_attr(sample, i) for i in attrs]
    return ret

def set_seq_update(collection, seq_update):
    """
    Set seq_update for current collection. 
    """
    with open(CONFIG_FILE, "r") as fl:
        config = yaml.safe_load(fl)
    config["collections"][collection]['seqUpdate'] = seq_update
    with open(CONFIG_FILE, "w") as fl:
        yaml.dump(config, fl, default_flow_style=False)

def get_seq_update(collection):
    """
    Get seqUpdate from file if no -> get from server with default date -> if no def date get (current date - 3)
    """
    with open(CONFIG_FILE, "r") as configuration_file:
        configuration = yaml.safe_load(configuration_file)
    seq_update = configuration['collections'][collection]['seqUpdate']
    if seq_update is not None:
        return seq_update
    else:
        default_date = configuration['collections'][collection]['default_date']
        if default_date is None:
            default_date = (datetime.datetime.now() - datetime.timedelta(days=3)).strftime("%Y-%m-%d")
            configuration['collections'][collection]['default_date'] = default_date
            with open(CONFIG_FILE, "w") as configuration_file:
                yaml.dump(configuration, configuration_file, default_flow_style=False)
            seq_update = poller.get_seq_update_by_date(collection, default_date)
            set_seq_update(collection, seq_update)
            return seq_update
        else:
            seq_update = poller.get_seq_update_by_date(collection, default_date)
            set_seq_update(collection, seq_update)
            return seq_update

def get_collection_dir(collection):
    """
    Get collection directory, if not exists -> create it. 
    """
    collection_dir = os.path.join(DATA_DIR, collection.replace("/", "_"))
    if not os.path.exists(collection_dir):
        os.makedirs(collection_dir)
    return collection_dir

def create_csv_file(collection, file_name):
    """
    Check file, if it doesn't exist, create it and write headers
    """
    file_location = get_collection_dir(collection)
    for fl in os.listdir(file_location):
        in_dir_object = os.path.join(file_location, fl)
        if os.path.isfile(in_dir_object):
            os.remove(in_dir_object)

    if collection in collections_fields.keys():
        headers = collections_fields[collection]
    elif collection in additional_fields.keys():
        headers = additional_fields[collection]

    with open(os.path.join(file_location, file_name), "w") as fl:
        fl.write(','.join(headers) + "\n")

def write_data_to_csv(data, collection):
    """
    Write data to csv file
    """
    file_location = os.path.join(get_collection_dir(collection), file_name)
    with open(file_location, "a", encoding="utf-8", newline="") as fl:
        fl_writer = csv.writer(fl, delimiter=",", quotechar = '"', quoting=csv.QUOTE_MINIMAL)
        for row in data:
            fl_writer.writerow(row)


##############
#  PROCESSORS
##############
        

def basic_processor(portion, collection):
    fields = collections_fields[collection]
    data = [find_attrs(i, fields) for i in portion]
    write_data_to_csv(data, collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))


def phishing_kit_processor(portion, collection):
    #headers = ["hash", "downloadedFrom/url", "downloadedFrom/domain", "emails", "targetBrand"]
    lines = [] 
    for item in portion:
        for downloaded_from in item.get("downloadedFrom"):
            lines.append([item.get("hash"), downloaded_from.get("url"), downloaded_from.get("domain"), None, None])
        for email in item.get("emails"):
            lines.append([item.get("hash"), None, None, email, None])
        for target_brand in item.get("targetBrand"):
            lines.append([item.get("hash"), None, None, None, target_brand])

    set_seq_update(collection, portion[-1].get("seqUpdate"))
    write_data_to_csv(lines, collection)

def threat_processor(portion, collection):
    #headers = ["id", "dateFirstSeen", "dateLastSeen", "datePublished", "threatActor/name", "indicators/params/ipv4", "indicators/params/hashes/md5", "indicators/params/hashes/sha1", "indicators/params/hashes/sha256"]
    lines = []
    for item in portion:
        for indicator in item.get("indicators"):
            if indicator.get("type") == "network":
                for ip in indicator.get("params").get("ipv4"):
                    lines.append([ item.get("id"), 
                                item.get("dateFirstSeen"),
                                item.get("dateLastSeen"),
                                item.get("datePublished"),
                                item.get("threatActor").get("name"),
                                ip,
                                None,
                                None,
                                None])
            elif indicator.get("type") == "file":
                lines.append([ item.get("id"),
                            item.get("dateFirstSeen"),
                            item.get("dateLastSeen"),
                            item.get("datePublished"),
                            item.get("threatActor").get("name"),
                            None,
                            indicator.get("params").get("hashes").get("md5"),
                            indicator.get("params").get("hashes").get("sha1"),
                            indicator.get("params").get("hashes").get("sha256")])
    
    write_data_to_csv(lines, collection)
    #headers = ["threat/id", "threatActor/name", "title", "attackTactic", "attackType", "tacticId"]
    
    mitre_matrix = []
    for threat in portion:
        if threat.get("mitreMatrix") != []:
            for matrix_line in threat.get("mitreMatrix"):
                mitre_matrix.append([   threat.get("id"),
                                        get_threat_actor(threat.get("threatActor")),
                                        threat.get("title"), 
                                        matrix_line.get("attackTactic"), 
                                        matrix_line.get("attackType"),
                                        matrix_line.get("id")])
    
    write_data_to_csv(mitre_matrix, collection + "/mitre_matrix")
    set_seq_update(collection, portion[-1].get("seqUpdate"))


def threat_actor_processor(portion, collection):
    #headers = ["createdAt", "name", "aliases", "labels", "lang"]
    lines = []
    for actor in portion:
        lines.append([actor.get("createdAt"), actor.get("name"), "|".join(actor.get("aliases")), "|".join(actor.get("labels")), "|".join(actor.get("langs"))])
    
    write_data_to_csv(lines, collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))


def git_leak_processor(portion, collection):
    #headers = ["dateDetected", "name", "repository", "matchesType", "revisions/info/authorEmail", "revisions/info/authorName", "revisions/info/dateCreated"]
    lines = []
    for leak in portion:
        for revision in leak.get("revisions"):
            lines.append([leak.get("dateDetected"), 
            leak.get("name"), 
            leak.get("repository"), 
            "|".join(leak.get("matchesType")), 
            revision.get('info').get("authorEmail"),
            revision.get('info').get("authorName"),
            revision.get('info').get("dateCreated")])
            
    write_data_to_csv(lines, collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))

def public_leak_processor(portion, collection):
    # headers = ["date_published", "created", "hash", "size", "matchType", "keyword", "link"],
    lines = []
    for leak in portion:
        date_published = leak.get("linkList")[0].get("datePublished")
        link = leak.get("linkList")[0].get("link")
        if leak.get("matches") != []:
            for match_type in leak.get("matches").keys():
                for key_word in leak.get("matches").get(match_type):
                    for key in leak.get("matches").get(match_type).get(key_word):
                        lines.append([date_published, leak.get("created"), leak.get("hash"), leak.get("size"), match_type, key , link])

    write_data_to_csv(lines,collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))




def osi_vulnerability_processor(portion, collection):
    #headers = ["datePublished","id", "cvss/score", "description", "reporter", "software/softwareName", "software/softwareVersionString", "software/vendor"]
    lines = []
    for vuln in portion:
        for soft in vuln.get('cpeTable'):
            lines.append([  vuln.get("datePublished"),
                            vuln.get("id"),
                            vuln.get("cvss").get("score"),
                            vuln.get("description").replace(",", " "),
                            vuln.get("reporter"),
                            soft.get("product"),
                            soft.get("version"),
                            soft.get("vendor")
            ])

    write_data_to_csv(lines,collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))


def get_threat_actor(thr_dict):
    if thr_dict is None:
        return None
    else:
        return thr_dict.get("name")

def get_malware(thr_dict):
    if len(thr_dict) == 0 :
        return None
    else:
        return thr_dict[0].get("name")

def escape_commas(desc):
    if desc is None:
        return None
    else:
        return desc.replace(",", " ")


def malware_cnc_processor(portion, collection):
    #headers = ["dateDetected", "dateLastSeen", "cnc", "ipv4/ip", "domain", "threatActor", "malwareList/name", "platform"]
    lines = []
    for cnc in portion:
        for ipv4 in cnc.get("ipv4"):
            lines.append([cnc.get("dateDetected"),
                          cnc.get("dateLastSeen"),
                          cnc.get("cnc"),
                          ipv4.get("ip"),
                          cnc.get("domain"),
                          get_threat_actor(cnc.get("threatActor")),
                          get_malware(cnc.get("malwareList")),
                          cnc.get("platform")
                    ])

    write_data_to_csv(lines, collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))


def malware_malware_processor(portion, collection):
    #headers = ["name", "platform", "shortDescription", "threatLevel"]
    lines = []
    for malware in portion:
        lines.append([malware.get("name"), malware.get("platform"), escape_commas(malware.get("shortDescription")), malware.get("threatLevel")])
    
    write_data_to_csv(lines, collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))


def targeted_malware_processor(portion, collection):
    #headers = ["date", "malware/name", "md5", "injectMd5", "threatActor/name", "fileName", "fileType", "size", "source" ]
    lines = []
    for tm in portion:
        lines.append([
            tm.get("date"),
            tm.get("malware").geT("name"),
            tm.get("md5"),
            tm.get("injectMd5"),
            get_threat_actor(tm.get("threatActor")),
            tm.get("fileName"),
            escape_commas(tm.get("fileType")),
            tm.get("size"),
            tm.get("source")
            ])
        
    write_data_to_csv(lines, collection)
    set_seq_update(collection, portion[-1].get("seqUpdate"))



processors = {
    "compromised/account": basic_processor,
    "compromised/card": basic_processor,
    "compromised/mule": basic_processor,
    "compromised/imei": basic_processor,
    "compromised/file": basic_processor,
    "attacks/ddos": basic_processor,
    "attacks/deface": basic_processor,
    "attacks/phishing": basic_processor,
    "attacks/phishing_kit": phishing_kit_processor,
    "bp/phishing": basic_processor,
    "bp/phishing_kit": phishing_kit_processor,
    "hi/threat": threat_processor,
    "hi/threat_actor": threat_actor_processor,
    "apt/threat": threat_processor,
    "apt/threat_actor": threat_actor_processor,
    "osi/git_leak": git_leak_processor,
    "osi/public_leak": public_leak_processor,
    "osi/vulnerability":osi_vulnerability_processor,
    "malware/cnc": malware_cnc_processor,
    "malware/malware": malware_malware_processor,
    "malware/targeted_malware": basic_processor,
    "suspicious_ip/tor_node": basic_processor,
    "suspicious_ip/open_proxy": basic_processor,
    "suspicious_ip/socks_proxy": basic_processor
}

def get_proxy_settings():
    if PROXY_USERNAME and PROXY_PASSWORD:
        return {PROXY_PROTOCOL : PROXY_PROTOCOL + "://" + str(PROXY_USERNAME) + ":" + str(PROXY_PASSWORD) + "@" + str(PROXY_ADDRESS) + ":" + str(PROXY_PORT)}
    elif PROXY_ADDRESS and PROXY_PORT:
        return {PROXY_PROTOCOL : PROXY_PROTOCOL + "://" + str(PROXY_ADDRESS) + ":" + str(PROXY_PORT)}
    else: 
        return None

        

if __name__ == "__main__":
    poller = APIClient(API_USERNAME, API_KEY, API_URL)
    poller.proxies = get_proxy_settings()
    logging.basicConfig(level=logging.DEBUG)
    for collection in processors.keys():
        with open(CONFIG_FILE, "r") as fl:
            config = yaml.safe_load(fl)

        limit = LIMIT if collection not in BIG_DATA_COLLECTIONS else BIG_DATA_LIMIT

        file_name = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S") + ".csv"

        if config['collections'][collection]['enable'] is True:
            
            if collection == "apt/threat":
                create_csv_file("apt/threat/mitre_matrix", file_name)
            elif collection == "hi/threat":
                create_csv_file("hi/threat/mitre_matrix", file_name)

            logging.info("Starting {} uploading session".format(collection))

            create_csv_file(collection, file_name)
            poller.init_update_session(collection, get_seq_update(collection), limit=limit, processor=processors[collection])

            logging.info("{} collection downloaded".format(collection))