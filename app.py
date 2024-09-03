import streamlit as st
import requests
import os
from datetime import datetime

# Custom CSS for styling
def apply_custom_css():
    st.markdown(
        """
        <style>
        body {
            background-color: #f5f5f5;
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            padding: 15px 32px;
            text-align: center;
            font-size: 16px;
            margin: 4px 2px;
            cursor: pointer;
        }
        .stTextInput>div>div>input {
            padding: 10px;
            margin-bottom: 10px;
        }
        .stTextInput>div>div>textarea {
            padding: 10px;
            margin-bottom: 10px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# Apply custom CSS
apply_custom_css()

# Function to store the access token and role
def store_token(token, role):
    st.session_state['access_token'] = token
    st.session_state['role'] = role
    st.session_state['page'] = 'dashboard'

# Function to retrieve the access token
def get_token():
    return st.session_state.get('access_token')

# Function to retrieve the role (user/admin)
def get_role():
    return st.session_state.get('role')

# Function to log messages without status codes
def log_message(message):
    log_dir = 'logs'
    log_file_path = f"{log_dir}/app_log.txt"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    with open(log_file_path, "a") as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")

# Function to display the profile with edit option
def display_profile(edit_mode=False):
    token = get_token()
    if token:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get("http://127.0.0.1:8000/api/profile/", headers=headers)

        if response.status_code == 200:
            profile = response.json()
            if edit_mode:
                st.title("Edit Profile")
                name = st.text_input("Name", profile['name'])
                phone_number = st.text_input("Phone Number", profile['phone_number'])
                employee_id = st.text_input("Employee ID", profile['employee_id'])

                if st.button("Save Changes"):
                    data = {
                        "name": name,
                        "phone_number": phone_number,
                        "employee_id": employee_id,
                    }

                    update_response = requests.put("http://127.0.0.1:8000/api/profile/update/", headers=headers, json=data)
                    if update_response.status_code == 200:
                        st.success("Profile updated successfully!")
                        st.session_state['page'] = 'dashboard'  # Switch back to the dashboard page
                        log_message("Profile updated successfully.")
                    else:
                        try:
                            error_message = update_response.json().get('detail', 'Error updating profile.')
                        except requests.exceptions.JSONDecodeError:
                            error_message = update_response.text
                            log_message(f"Error decoding JSON response: {update_response.text}")
                            print(f"Error decoding JSON response. Raw response: {update_response.text}")  # Log to console
                        log_message(f"Profile update failed: {error_message}")
                        print(f"Failed to update profile. Response: {error_message}")  # Log to console
            else:
                st.write(f"Name: {profile['name']}")
                st.write(f"Email: {profile['email']}")
                st.write(f"Phone Number: {profile['phone_number']}")
                st.write(f"Employee ID: {profile['employee_id']}")
                if st.button("Edit Profile"):
                    st.session_state['page'] = 'edit_profile'
                if st.button("Change Password"):
                    st.session_state['page'] = 'change_password'
        else:
            if response.status_code == 401:
                st.error("Session expired. Please log in again.")
                st.session_state.pop('access_token', None)
                st.session_state['page'] = 'login'
                log_message("Session expired, user logged out.")
            else:
                try:
                    error_message = response.json().get('detail', 'Error loading profile.')
                except requests.exceptions.JSONDecodeError:
                    error_message = response.text
                    log_message(f"Error decoding JSON response: {response.text}")
                    print(f"Error decoding JSON response. Raw response: {response.text}")  # Log to console
                log_message(f"Profile load failed: {error_message}")
                print(f"Failed to load profile. Response: {error_message}")  # Log to console
    else:
        st.warning("You need to log in first.")

# Function to display all profiles (Admin view)
def display_all_profiles():
    token = get_token()
    if token:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get("http://127.0.0.1:8000/api/users/", headers=headers)

        if response.status_code == 200:
            try:
                profiles = response.json()
                for profile in profiles:
                    st.write(f"Name: {profile['name']}")
                    st.write(f"Email: {profile['email']}")
                    st.write(f"Phone Number: {profile['phone_number']}")
                    st.write(f"Employee ID: {profile['employee_id']}")
                    if st.button(f"Delete User {profile['email']}"):
                        delete_response = requests.delete(f"http://127.0.0.1:8000/api/users/{profile['id']}/", headers=headers)
                        if delete_response.status_code == 200:
                            st.success("User deleted successfully!")
                            log_message(f"User {profile['email']} deleted successfully.")
                        else:
                            try:
                                error_message = delete_response.json().get('detail', 'Error deleting user.')
                            except requests.exceptions.JSONDecodeError:
                                error_message = delete_response.text
                                log_message(f"Error decoding JSON response: {delete_response.text}")
                                print(f"Error decoding JSON response. Raw response: {delete_response.text}")  # Log to console
                            log_message(f"User delete failed: {error_message}")
                            print(f"Failed to delete user. Response: {error_message}")  # Log to console
                    st.write("---")
            except requests.exceptions.JSONDecodeError:
                log_message("Failed to decode JSON response from server. Please ensure the server is running correctly.")
                print("Failed to decode JSON response from server. Please ensure the server is running correctly.")  # Log to console
        else:
            if response.status_code == 401:
                st.error("Session expired. Please log in again.")
                st.session_state.pop('access_token', None)
                st.session_state['page'] = 'login'
                log_message("Session expired, admin logged out.")
            else:
                try:
                    error_message = response.json().get('detail', 'Error loading profiles.')
                except requests.exceptions.JSONDecodeError:
                    error_message = response.text
                    log_message(f"Error decoding JSON response: {response.text}")
                    print(f"Error decoding JSON response. Raw response: {response.text}")  # Log to console
                log_message(f"Profiles load failed: {error_message}")
                print(f"Failed to load profiles. Response: {error_message}")  # Log to console
    else:
        st.warning("You need to log in first.")

# Function to display change password form
def change_password():
    st.title("Change Password")
    current_password = st.text_input("Current Password", type="password")
    new_password = st.text_input("New Password", type="password")

    if st.button("Submit"):
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        data = {
            "current_password": current_password,
            "new_password": new_password,
        }

        response = requests.put("http://127.0.0.1:8000/api/profile/change-password/", headers=headers, json=data)

        if response.status_code == 200:
            st.success("Password updated successfully!")
            st.session_state['page'] = 'dashboard'
            log_message("Password updated successfully.")
        else:
            try:
                error_message = response.json().get('detail', 'Failed to change password.')
            except requests.exceptions.JSONDecodeError:
                error_message = response.text
                log_message(f"Error decoding JSON response: {response.text}")
                print(f"Error decoding JSON response. Raw response: {response.text}")  # Log to console
            log_message(f"Password change failed: {error_message}")
            print(f"Failed to change password. Response: {error_message}")  # Log to console

# Function to create a new user (Admin)
def add_user_form():
    st.title("Add New User")
    email = st.text_input("Email")
    name = st.text_input("Name")
    phone_number = st.text_input("Phone Number")
    employee_id = st.text_input("Employee ID")
    password = st.text_input("Password", type="password")

    if st.button("Create User"):
        token = get_token()  # Retrieve the token stored in session
        headers = {"Authorization": f"Bearer {token}"}  # Include token in headers
        
        data = {
            "email": email,
            "name": name,
            "phone_number": phone_number,
            "employee_id": employee_id,
            "password": password,
        }

        response = requests.post("http://127.0.0.1:8000/api/users/", headers=headers, json=data)  # Use JSON format for the request

        if response.status_code == 201:
            st.success("User created successfully!")
            st.session_state['page'] = 'dashboard'
            log_message(f"User {email} created successfully.")
        else:
            try:
                error_message = response.json().get('detail', 'No additional error message provided.')
            except requests.exceptions.JSONDecodeError:
                error_message = response.text
                log_message(f"Error decoding JSON response: {response.text}")
                print(f"Error decoding JSON response. Raw response: {response.text}")  # Log to console
            log_message(f"User creation failed: {error_message}")
            print(f"Failed to create user. Response: {error_message}")  # Log to console

    if st.button("Cancel"):
        st.session_state['page'] = 'dashboard'

# Main app logic
if 'page' not in st.session_state:
    st.session_state['page'] = 'login'

if st.session_state['page'] == 'login':
    st.title("User Management System")

    user_action = st.radio("Action", ["Login", "Signup", "Forgot Password"])

    if user_action == "Signup":
        st.title("Signup")

        # Signup form
        email = st.text_input("Email")
        name = st.text_input("Name")
        phone_number = st.text_input("Phone Number")
        employee_id = st.text_input("Employee ID")
        password = st.text_input("Password", type="password")

        if st.button("Signup"):
            # Password validation
            if len(password) < 8:
                st.error("Password must be at least 8 characters long.")
            elif not any(char in "@#%&*!" for char in password):
                st.error("Password must contain at least one special character (@, #, %, &, *, !).")
            elif not any(char.isupper() for char in password):
                st.error("Password must contain at least one uppercase letter.")
            elif not any(char.isdigit() for char in password):
                st.error("Password must contain at least one digit.")
            else:
                api_url = "http://127.0.0.1:8000/api/register/"

                data = {
                    "email": email,
                    "name": name,
                    "phone_number": phone_number,
                    "employee_id": employee_id,
                    "password": password,
                }

                response = requests.post(api_url, json=data)

                # Handle the response
                if response.status_code == 201:
                    st.success("Signup successful! Please login.")
                    st.session_state['page'] = 'login'
                    log_message(f"User {email} registered successfully.")
                else:
                    try:
                        error_message = response.json().get('detail', 'Signup failed.')
                    except requests.exceptions.JSONDecodeError:
                        error_message = response.text
                        log_message(f"Error decoding JSON response: {response.text}")
                        print(f"Error decoding JSON response. Raw response: {response.text}")  # Log to console
                    log_message(f"Signup failed: {error_message}")
                    print(f"Signup failed. Response: {error_message}")  # Log to console

    elif user_action == "Login":
        st.title("Login")

        # Login form
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        role = st.radio("Are you logging in as?", ["User", "Admin"])

        if st.button("Login"):
            api_url = "http://127.0.0.1:8000/api/token/"
            data = {
                "email": email,
                "password": password,
            }
            response = requests.post(api_url, json=data)

            if response.status_code == 200:
                access_token = response.json().get('access')
                role_type = "user" if role == "User" else "admin"
                store_token(access_token, role_type)
                st.success("Login successful!")
                st.session_state['page'] = 'dashboard'
                log_message(f"User {email} logged in successfully.")
            else:
                try:
                    error_message = response.json().get('detail', 'Login failed.')
                except requests.exceptions.JSONDecodeError:
                    error_message = response.text
                    log_message(f"Error decoding JSON response: {response.text}")
                    print(f"Error decoding JSON response. Raw response: {response.text}")  # Log to console
                log_message(f"Login failed: {error_message}")
                print(f"Login failed. Response: {error_message}")  # Log to console

    elif user_action == "Forgot Password":
        st.title("Forgot Password")

        email = st.text_input("Enter your email address")

        if st.button("Send Reset Link"):
            api_url = "http://127.0.0.1:8000/api/request-reset-email/"
            data = {
                "email": email,
            }
            response = requests.post(api_url, json=data)

            if response.status_code == 200:
                st.success("Password reset link has been sent to your email.")
                log_message(f"Password reset requested for {email}.")
            else:
                try:
                    error_message = response.json().get('detail', 'Failed to send reset link.')
                except requests.exceptions.JSONDecodeError:
                    error_message = response.text
                    log_message(f"Error decoding JSON response: {response.text}")
                    print(f"Error decoding JSON response. Raw response: {response.text}")  # Log to console
                log_message(f"Password reset request failed: {error_message}")
                print(f"Failed to send reset link. Response: {error_message}")  # Log to console

elif st.session_state['page'] == 'dashboard':
    role = get_role()

    if role == "user":
        display_profile()
        if st.button("Logout"):
            st.session_state.pop('access_token', None)
            st.session_state['page'] = 'login'
            log_message("User logged out.")

    elif role == "admin":
        display_all_profiles()
        if st.button("Add New User"):
            st.session_state['page'] = 'add_user'
        if st.button("Logout"):
            st.session_state.pop('access_token', None)
            st.session_state['page'] = 'login'
            log_message("Admin logged out.")

elif st.session_state['page'] == 'edit_profile':
    display_profile(edit_mode=True)
    if st.button("Cancel"):
        st.session_state['page'] = 'dashboard'

elif st.session_state['page'] == 'change_password':
    change_password()
    if st.button("Cancel"):
        st.session_state['page'] = 'dashboard'

elif st.session_state['page'] == 'add_user':
    add_user_form()