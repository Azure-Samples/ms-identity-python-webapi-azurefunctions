import sys
import logging
import azure.functions as func

from azf_wsgi import AzureFunctionsWsgi

sys.path.insert(0,"./secureFlaskApp/")
from secureFlaskApp import app as application

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    return AzureFunctionsWsgi(application).main(req)