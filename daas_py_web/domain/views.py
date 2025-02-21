import requests
import base64
from django.shortcuts import render, redirect
from django.contrib import messages
from requests.auth import HTTPBasicAuth
from manage import logger, config

API_BASE_URL = "http://127.0.0.1"
LOGIN_URL = f"{API_BASE_URL}:9000/api/auth/login/"
ACCOUNT_URL = f"{API_BASE_URL}:9001/api/account/db/?facility=ALL"
FACILITY_URL = f"{API_BASE_URL}:9002/api/facility/db/?facility=ALL"
ASSET_URL = f"{API_BASE_URL}:9003/api/asset/db/?facility=ALL"
SERVICE_URL = f"{API_BASE_URL}:9004/api/service/db/?facility=ALL"

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
        response = requests.post(LOGIN_URL, headers=headers)

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

    headers = {"Authorization": f"Bearer {token}"}  # Add Bearer token authentication

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
        "account": fetch_data(ACCOUNT_URL, request),
        "facility": fetch_data(FACILITY_URL, request),
        "asset": fetch_data(ASSET_URL, request),
        "service": fetch_data(SERVICE_URL, request),
    }

    return render(request, "dashboard.html", context)

    return render(request, "dashboard.html", context)


def logout_view(request):
    """Logout and clear session."""
    request.session.flush()  # Clear session data
    messages.success(request, "Logged out successfully!")
    return redirect("login")

