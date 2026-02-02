from thehive4py.api import TheHiveApi
from thehive4py.models import Case
import time

# Connect to local docker instance
# NOTE: You will need to create an API key in TheHive UI first!
API_URL = 'http://localhost:9000'
API_KEY = 'PASTE_YOUR_KEY_HERE_LATER'

def connect_to_hive():
    api = TheHiveApi(API_URL, API_KEY)
    return api

if __name__ == "__main__":
    print("Risk Engine Starting...")
    # Your logic will go here