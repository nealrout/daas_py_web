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
    "ACCOUNT_SEARCH": f"{API_BASE_URL}:{API_PORTS['account']}/api/account/db/?facility=ALL",
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

        # Send login request with Basic Authentication
        response = requests.post(API_ENDPOINTS["LOGIN"], headers=headers)

        if response.status_code == 200:
            data = response.json()
            access_token = data.get("access")  # Extract the access token
            refresh_token = data.get("refresh")  # (Optional) Store refresh token if needed

            if access_token:
                request.session["auth_token"] = access_token  # Store the token in session
                request.session["refresh_token"] = refresh_token  # Store refresh token for later use
                messages.success(request, "Login successful!")
                return redirect("dashboard")  # Redirect to the dashboard
            else:
                messages.error(request, "Login failed. No access token received.")
        else:
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, "login.html")

def fetch_data(endpoint, request):
    """Fetch data from the API using the stored access token."""
    token = request.session.get("auth_token")
    if not token:
        return {"error": "User is not authenticated"}

    headers = {"Authorization": f"Bearer {token}"}

    logger.debug(f"URL: {endpoint}")
    response = requests.get(f"{endpoint}", headers=headers)

    print(response)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401:  # Token expired or unauthorized
        return {"error": "Unauthorized. Please log in again."}
    return {"error": "Failed to retrieve data"}

def dashboard_view(request):
    """Display dashboard after successful login."""
    token = request.session.get("auth_token")
    if not token:
        return redirect("login")  # Redirect to login if not authenticated

    context = {
        "account": fetch_data(API_ENDPOINTS["ACCOUNT_SEARCH"], request),
        "facility": fetch_data(API_ENDPOINTS["FACILITY_SEARCH"], request),
        "asset": fetch_data(API_ENDPOINTS["ASSET_SEARCH"], request),
        "service": fetch_data(API_ENDPOINTS["SERVICE_SEARCH"], request),
    }

    return render(request, "dashboard.html", context)

    return render(request, "dashboard.html", context)

def logout_view(request):
    """Logout and clear session."""
    request.session.flush()  # Clear session data
    messages.success(request, "Logged out successfully!")
    return redirect("login")

def index(request):
    token = request.session.get("auth_token")
    if not token:
        return redirect("login") 
    
    return render(request, 'index.html')

def get_users(request):
    token = request.session.get("auth_token")
    if not token:
        return {"error": "User is not authenticated"}

    headers = {"Authorization": f"Bearer {token}"}

    response = requests.post(API_ENDPOINTS["USER_SEARCH"], json={}, headers=headers)
    users = response.json() if response.status_code == 200 else []
    return JsonResponse(users, safe=False)

def get_facilities(request):
    token = request.session.get("auth_token")
    if not token:
        return {"error": "User is not authenticated"}

    headers = {"Authorization": f"Bearer {token}"}

    response = requests.post(API_ENDPOINTS["FACILITY_SEARCH"], headers=headers, json={})
    facilities = response.json() if response.status_code == 200 else []
    return JsonResponse(facilities, safe=False)

def get_user_facilities(request, username):
    token = request.session.get("auth_token")
    if not token:
        return {"error": "User is not authenticated"}

    headers = {"Authorization": f"Bearer {token}"}

    response = requests.post(API_ENDPOINTS["USERFACILITY_SEARCH"], headers=headers, json={"username": [username]})
    user_facilities = response.json() if response.status_code == 200 else []
    return JsonResponse(user_facilities, safe=False)

def update_user_facilities(request):
    token = request.session.get("auth_token")
    if not token:
        return {"error": "User is not authenticated"}

    headers = {"Authorization": f"Bearer {token}"}

    if request.method == "POST":
        data = request.POST
        username = data.get("username")
        facility_nbr = request.POST.getlist("facility_nbr[]")
        
        response = requests.post(API_ENDPOINTS["USERFACILITY_UPSERT"], headers=headers, json={"username": username, "facility_nbr": facility_nbr})
        return JsonResponse(response.json(), safe=False)
    
    return JsonResponse({"error": "Invalid request"}, status=400)
