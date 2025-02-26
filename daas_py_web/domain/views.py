import requests
import base64
from django.shortcuts import render, redirect
from django.contrib import messages
from requests.auth import HTTPBasicAuth
from manage import logger, config
from django.http import JsonResponse

configs = config.get_configs()

API_BASE_URL = "http://127.0.0.1"
API_PORTS = {
    "auth": int(configs.AUTH_PORT),
    "account": int(configs.DOMAIN_PORT_ACCOUNT),
    "facility": int(configs.DOMAIN_PORT_FACILITY),
    "asset": int(configs.DOMAIN_PORT_ASSET),
    "service": int(configs.DOMAIN_PORT_SERVICE),
    "user": int(configs.DOMAIN_PORT_USER),
    "userfacility": int(configs.DOMAIN_PORT_USERFACILITY),
}

API_ENDPOINTS = {
    "LOGIN": f"{API_BASE_URL}:{API_PORTS['auth']}/api/auth/login/",
    # "ACCOUNT_SEARCH": f"{API_BASE_URL}:{API_PORTS['account']}/api/account/db/?facility=ALL",
    "ACCOUNT_SEARCH": f"{API_BASE_URL}:{API_PORTS['account']}/api/account/cache/query?facility=ALL",
    "ASSET_SEARCH": f"{API_BASE_URL}:{API_PORTS['asset']}/api/asset/db/?facility=ALL",
    "SERVICE_SEARCH": f"{API_BASE_URL}:{API_PORTS['service']}/api/service/db/?facility=ALL",
    "FACILITY_SEARCH": f"{API_BASE_URL}:{API_PORTS['facility']}/api/facility/db/?facility=ALL",
    "FACILITY_UPSERT": f"{API_BASE_URL}:{API_PORTS['facility']}/api/facility/db/upsert/?facility=ALL",
    "USER_SEARCH": f"{API_BASE_URL}:{API_PORTS['user']}/api/user/db/?facility=ALL",
    "USER_UPSERT": f"{API_BASE_URL}:{API_PORTS['user']}/api/user/db/upsert/?facility=ALL",
    "USERFACILITY_SEARCH": f"{API_BASE_URL}:{API_PORTS['userfacility']}/api/userfacility/db/?facility=ALL",
    "USERFACILITY_UPSERT": f"{API_BASE_URL}:{API_PORTS['userfacility']}/api/userfacility/db/upsert/?facility=ALL",
}

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            messages.error(request, "Username and password are required.")
            return render(request, "login.html")

        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        headers = {"Authorization": f"Basic {encoded_credentials}"}

        try:
            response = requests.post(API_ENDPOINTS["LOGIN"], headers=headers)
            response.raise_for_status()

            data = response.json()
            access_token = data.get("access")
            refresh_token = data.get("refresh")

            if access_token:
                request.session["auth_token"] = access_token
                request.session["refresh_token"] = refresh_token
                messages.success(request, "Login successful!")
                return redirect("dashboard")
            else:
                messages.error(request, "Login failed. No access token received.")

        except requests.exceptions.RequestException as e:
            logger.exception(f"❌Login request failed: {e}")
            messages.error(request, "Failed to connect to authentication service. Please try again.")
        
        except Exception as e:
            logger.exception(f"❌Unexpected error in login_view: {e}")
            messages.error(request, "An unexpected error occurred. Please try again.")

    return render(request, "login.html")

def fetch_data(endpoint, request):
    token = request.session.get("auth_token")
    if not token:
        return {"error": "User is not authenticated"}

    headers = {"Authorization": f"Bearer {token}"}

    try:
        logger.debug(f"Fetching data from: {endpoint}")
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        return response.json()
    
    except requests.exceptions.RequestException as e:
        logger.exception(f"❌Failed to fetch data from {endpoint}: {e}")
        return {"error": "Failed to retrieve data"}
    
    except Exception as e:
        logger.exception(f"❌Unexpected error in fetch_data: {e}")
        return {"error": "An unexpected error occurred"}

def dashboard_view(request):
    """Render the dashboard page with tabbed navigation"""
    if not request.session.get("auth_token"):
        return redirect("login")
    return render(request, "dashboard.html")

def fetch_tab_data(request, tab_name):
    """Fetch data based on the selected tab (Account, Facility, Asset, Service)"""
    if tab_name.upper()+"_SEARCH" not in API_ENDPOINTS:
        return JsonResponse({"error": "Invalid tab selected"}, status=400)
    
    search_query = request.GET.get("search", "").strip()

    payload = {"q": "*:*", "rows": configs.SOLR_MAX_ROW}

    if tab_name.upper() == configs.DOMAIN_NAME_ACCOUNT:
        if search_query:
            fq = {"fq": f"account_nbr:(*{search_query}*) OR account_code:(*{search_query}*) OR account_name:(*{search_query}*)"}
            payload = {**payload, **fq} 

        logger.debug(f"payload: {payload}")
        return fetch_json_response_cache(tab_name.upper() + "_SEARCH", request, payload)
        
    elif tab_name.upper() == configs.DOMAIN_NAME_FACILITY:
        logger.debug("")
    elif tab_name.upper() == configs.DOMAIN_NAME_ASSET:
        logger.debug("")
    elif tab_name.upper() == configs.DOMAIN_NAME_SERVICE:
        logger.debug("")

    # payload = {"search": search_query} if search_query else {}
    
    logger.debug(f"search_query: {search_query}")
    # logger.debug(f"search payload: {payload}")
    
    return fetch_json_response_db(tab_name.upper() + "_SEARCH", request)

def dashboard_og_view(request):
    token = request.session.get("auth_token")
    if not token:
        return redirect("login")

    context = {
        "account": fetch_data(API_ENDPOINTS["ACCOUNT_SEARCH"], request),
        "facility": fetch_data(API_ENDPOINTS["FACILITY_SEARCH"], request),
        "asset": fetch_data(API_ENDPOINTS["ASSET_SEARCH"], request),
        "service": fetch_data(API_ENDPOINTS["SERVICE_SEARCH"], request),
    }

    return render(request, "dashboard_og.html", context)

def logout_view(request):
    """Logs out the user and clears the session."""
    try:
        request.session.flush()
        messages.success(request, "Logged out successfully!")
    except Exception as e:
        logger.exception(f"❌Logout error: {e}")
        messages.error(request, "An error occurred while logging out.")
    return redirect("login")

def index(request):
    token = request.session.get("auth_token")
    if not token:
        return redirect("login")  
    return render(request, "index.html")

def userfacility_assignment(request):
    """Handles the index page and redirects to login if unauthenticated."""
    token = request.session.get("auth_token")
    if not token:
        return redirect("login")  
    return render(request, "userfacility_assignment.html")


def get_account(request):
    return fetch_json_response_db("ACCOUNT_SEARCH", request)

def get_facility(request):
    return fetch_json_response_db("FACILITY_SEARCH", request)

def get_asset(request):
    return fetch_json_response_db("ASSET_SEARCH", request)

def get_service(request):
    return fetch_json_response_db("SERVICE_SEARCH", request)

def get_user(request):
    return fetch_json_response_db("USER_SEARCH", request)

def get_user_facility(request, username):
    return fetch_json_response_db("USERFACILITY_SEARCH", request, {"username": [username]})

def update_user_facility(request):
    if request.method == "POST":
        return fetch_json_response_db("USERFACILITY_UPSERT", request, {
            "username": request.POST.get("username"),
            "facility_nbr": request.POST.getlist("facility_nbr[]"),
        })
    return JsonResponse({"error": "Invalid request"}, status=400)

def fetch_json_response_db(endpoint_key, request, payload=None):
    """Helper function to handle API requests with exception handling."""
    
    token = request.session.get("auth_token")
    if not token:
        return JsonResponse({"error": "User is not authenticated"}, status=401)

    headers = {"Authorization": f"Bearer {token}"}
    payload = payload or {}

    try:
        response = requests.post(API_ENDPOINTS[endpoint_key], headers=headers, json=payload)
        response.raise_for_status()
        return JsonResponse(response.json(), safe=False)
    
    except requests.exceptions.HTTPError as e:
        logger.exception(f"❌HTTP error while accessing {endpoint_key}: {e}")
        return JsonResponse({"error": f"HTTP error: {response.status_code}"}, status=response.status_code)
    
    except requests.exceptions.RequestException as e:
        logger.exception(f"❌Request failed for {endpoint_key}: {e}")
        return JsonResponse({"error": "Failed to connect to the API"}, status=500)
    
    except Exception as e:
        logger.exception(f"❌Unexpected error in {endpoint_key}: {e}")
        return JsonResponse({"error": "An unexpected error occurred"}, status=500)

def fetch_json_response_cache(endpoint_key, request, payload=None):
    """Helper function to handle API requests with exception handling."""
    
    token = request.session.get("auth_token")
    if not token:
        return JsonResponse({"error": "User is not authenticated"}, status=401)

    headers = {"Authorization": f"Bearer {token}"}
    payload = payload or {}

    try:
        response = requests.post(API_ENDPOINTS[endpoint_key], headers=headers, json=payload)
        logger.debug(f"Response Status: {response.status_code}")
        
        response.raise_for_status()  # Raise an error for HTTP failures

        # Parse JSON response
        response_json = response.json()
        docs = response_json.get("response", {}).get("docs", [])  # Extract only "docs"

        logger.debug(f"Returning {len(docs)} documents from Solr response")

        return JsonResponse(docs, safe=False)  # Return only the docs array
    
    except requests.exceptions.HTTPError as e:
        logger.exception(f"❌HTTP error while accessing {endpoint_key}: {e}")
        return JsonResponse({"error": f"HTTP error: {response.status_code}"}, status=response.status_code)
    
    except requests.exceptions.RequestException as e:
        logger.exception(f"❌Request failed for {endpoint_key}: {e}")
        return JsonResponse({"error": "Failed to connect to the API"}, status=500)
    
    except Exception as e:
        logger.exception(f"❌Unexpected error in {endpoint_key}: {e}")
        return JsonResponse({"error": "An unexpected error occurred"}, status=500)
