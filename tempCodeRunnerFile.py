import streamlit as st
import requests

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

                    update_response = requests.put("http://127.0.0.1:8000/api/profile/update/", headers=headers, data=data)
                    if update_response.status_code == 200:
                        st.success("Profile updated successfully!")
                        st.session_state['page'] = 'dashboard'  # Switch back to the dashboard page
                    else:
                        st.error(f"Failed to update profile. Status code: {update_response.status_code}, Response: {update_response.text}")
            else:
                st.write(f"Name: {profile['name']}")
                st.write(f"Email: {profile['email']}")
                st.write(f"Phone Number: {profile['phone_number']}")
                st.write(f"Employee ID: {profile['employee_id']}")
                if st.button("Edit Profile"):
                    st.session_state['page'] = 'edit_profile'
        else:
            st.error(f"Failed to load profile. Status code: {response.status_code}, Response: {response.text}")
    else:
        st.warning("You need to log in first.")

# Function to display all profiles (Admin view)
def display_all_profiles():
    token = get_token()
    if token:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get("http://127.0.0.1:8000/api/admin/users/", headers=headers)

        if response.status_code == 200:
            profiles = response.json()
            for profile in profiles:
                st.write(f"Name: {profile['name']}")
                st.write(f"Email: {profile['email']}")
                st.write(f"Phone Number: {profile['phone_number']}")
                st.write(f"Employee ID: {profile['employee_id']}")
                st.write("---")
        else:
            st.error(f"Failed to load profiles. Status code: {response.status_code}, Response: {response.text}")
    else:
        st.warning("You need to log in first.")

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

                response = requests.post(api_url, data=data)

                # Handle the response
                if response.status_code == 201:
                    st.success("Signup successful! Please login.")
                    st.session_state['page'] = 'login'
                else:
                    st.error(f"Signup failed. Status code: {response.status_code}, Response: {response.text}")

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
            response = requests.post(api_url, data=data)

            if response.status_code == 200:
                access_token = response.json().get('access')
                role_type = "user" if role == "User" else "admin"
                store_token(access_token, role_type)
                st.success("Login successful!")
                st.session_state['page'] = 'dashboard'
            else:
                st.error("Login failed. Please try again.")

    elif user_action == "Forgot Password":
        st.title("Forgot Password")

        email = st.text_input("Enter your email address")

        if st.button("Send Reset Link"):
            api_url = "http://127.0.0.1:8000/api/request-reset-email/"
            data = {
                "email": email,
            }
            response = requests.post(api_url, data=data)

            if response.status_code == 200:
                st.success("Password reset link has been sent to your email.")
            else:
                st.error(f"Failed to send reset link. Status code: {response.status_code}, Response: {response.text}")

elif st.session_state['page'] == 'dashboard':
    role = get_role()

    if role == "user":
        display_profile()
        if st.button("Logout"):
            st.session_state.pop('access_token', None)
            st.session_state['page'] = 'login'

    elif role == "admin":
        display_all_profiles()
        if st.button("Logout"):
            st.session_state.pop('access_token', None)
            st.session_state['page'] = 'login'

elif st.session_state['page'] == 'edit_profile':
    display_profile(edit_mode=True)
    if st.button("Cancel"):
        st.session_state['page'] = 'dashboard'
