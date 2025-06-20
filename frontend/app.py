import streamlit as st
import requests
import re

st.set_page_config(page_title="Online Identity Verification System")

BASE_URL = "http://backend:8000"  # Update to "http://localhost:8000" if testing locally without Docker

def validate_cnic(cnic):
    return bool(re.match(r"^\d{13,15}$", cnic))

def validate_phone(phone):
    return bool(re.match(r"^\d{11}$", phone))

def login():
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        try:
            response = requests.post(f"{BASE_URL}/users/login", json={"email": email, "password": password})
            if response.status_code == 200:
                st.session_state.token = response.json()["access_token"]
                # Fetch user profile to get user_id
                headers = {"Authorization": f"Bearer {st.session_state.token}"}
                profile_resp = requests.get(f"{BASE_URL}/users/email/{email}", headers=headers)
                if profile_resp.status_code == 200:
                    user = profile_resp.json()
                    st.session_state.user_id = user["id"]
                else:
                    st.session_state.user_id = None
                st.success("Logged in successfully!")
                st.experimental_rerun()  # Refresh to show sidebar
            else:
                st.error(response.json().get("detail", "Login failed"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")

def register():
    st.subheader("Register")
    name = st.text_input("Name")
    cnic = st.text_input("CNIC")
    email = st.text_input("Email")
    phone = st.text_input("Phone")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if not validate_cnic(cnic):
            st.error("CNIC must be 13-15 digits")
            return
        if not validate_phone(phone):
            st.error("Phone must be 11 digits")
            return
        try:
            response = requests.post(f"{BASE_URL}/users/register", json={
                "name": name,
                "cnic": cnic,
                "email": email,
                "phone": phone,
                "password": password
            })
            if response.status_code == 200:
                st.success("Registered successfully! You can now log in.")
            else:
                st.error(response.json().get("detail", "Registration failed"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")

def view_profile():
    st.subheader("View Profile")
    user_id = st.number_input("Enter User ID", min_value=1, step=1)
    if st.button("View"):
        try:
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            response = requests.get(f"{BASE_URL}/users/{user_id}", headers=headers)
            if response.status_code == 200:
                user = response.json()
                st.session_state.user_id = user_id
                st.write(f"Name: {user['name']}")
                st.write(f"CNIC: {user['cnic']}")
                st.write(f"Email: {user['email']}")
                st.write(f"Phone: {user['phone']}")
                st.write(f"Created At: {user['created_at']}")
            else:
                st.error(response.json().get("detail", "Error fetching user"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")

def view_profile_by_email():
    st.subheader("View Profile by Email")
    email = st.text_input("Enter User Email")
    if st.button("View by Email"):
        try:
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            response = requests.get(f"{BASE_URL}/users/email/{email}", headers=headers)
            if response.status_code == 200:
                user = response.json()
                st.session_state.user_id = user["id"]
                st.write(f"Name: {user['name']}")
                st.write(f"CNIC: {user['cnic']}")
                st.write(f"Email: {user['email']}")
                st.write(f"Phone: {user['phone']}")
                st.write(f"Created At: {user['created_at']}")
            else:
                st.error(response.json().get("detail", "Error fetching user"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")

def view_all_users():
    st.subheader("All Users")
    try:
        headers = {"Authorization": f"Bearer {st.session_state.token}"}
        response = requests.get(f"{BASE_URL}/users/", headers=headers)
        if response.status_code == 200:
            users = response.json()
            for user in users:
                st.write(f"ID: {user['id']}, Name: {user['name']}, Email: {user['email']}")
        else:
            st.error(response.json().get("detail", "Error fetching users"))
    except requests.RequestException as e:
        st.error(f"Failed to connect to the server: {e}")

def update_profile():
    st.subheader("Update Profile")
    name = st.text_input("New Name (optional)")
    email = st.text_input("New Email (optional)")
    phone = st.text_input("New Phone (optional)")
    password = st.text_input("New Password (optional)", type="password")
    if st.button("Update"):
        if phone and not validate_phone(phone):
            st.error("Phone must be 11 digits")
            return
        data = {}
        if name: data["name"] = name
        if email: data["email"] = email
        if phone: data["phone"] = phone
        if password: data["password"] = password
        try:
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            user_id = st.session_state.get("user_id")
            if not user_id:
                st.error("User ID not found in session. Please view your profile first.")
                return
            response = requests.put(f"{BASE_URL}/users/{user_id}", headers=headers, json=data)
            if response.status_code == 200:
                st.success("Profile updated successfully!")
            else:
                st.error(response.json().get("detail", "Update failed"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")

def delete_profile():
    st.subheader("Delete Profile")
    if st.button("Delete"):
        try:
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            user_id = st.session_state.get("user_id")
            if not user_id:
                st.error("User ID not found in session. Please view your profile first.")
                return
            response = requests.delete(f"{BASE_URL}/users/{user_id}", headers=headers)
            if response.status_code == 204:
                st.success("Profile deleted successfully!")
                st.session_state.user_id = None
                st.experimental_rerun()
            else:
                st.error(response.json().get("detail", "Deletion failed"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")

def admin_login():
    st.subheader("Admin Login")
    email = st.text_input("Admin Email", key="admin_email")
    password = st.text_input("Admin Password", type="password", key="admin_password")
    if st.button("Admin Login"):
        try:
            response = requests.post(f"{BASE_URL}/users/login", json={"email": email, "password": password})
            if response.status_code == 200:
                st.session_state.token = response.json()["access_token"]
                headers = {"Authorization": f"Bearer {st.session_state.token}"}
                profile_resp = requests.get(f"{BASE_URL}/users/email/{email}", headers=headers)
                if profile_resp.status_code == 200:
                    user = profile_resp.json()
                    st.session_state.user_id = user["id"]
                    st.session_state.is_admin = user.get("is_admin", False)
                else:
                    st.session_state.user_id = None
                    st.session_state.is_admin = False
                st.success("Admin logged in successfully!")
                st.experimental_rerun()
            else:
                st.error(response.json().get("detail", "Login failed"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")

def admin_dashboard():
    st.title("Admin Dashboard")
    st.sidebar.title("Admin Menu")
    menu = st.sidebar.radio("Select Option", ["View All Users", "Add User", "Edit User", "Delete User", "Logout"])
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    if menu == "View All Users":
        st.subheader("All Users")
        try:
            response = requests.get(f"{BASE_URL}/admin/users", headers=headers)
            if response.status_code == 200:
                users = response.json()
                for user in users:
                    st.write(f"ID: {user['id']}, Name: {user['name']}, Email: {user['email']}, Admin: {user['is_admin']}")
            else:
                st.error(response.json().get("detail", "Error fetching users"))
        except requests.RequestException as e:
            st.error(f"Failed to connect to the server: {e}")
    elif menu == "Add User":
        st.subheader("Add New User")
        name = st.text_input("Name", key="add_name")
        cnic = st.text_input("CNIC", key="add_cnic")
        email = st.text_input("Email", key="add_email")
        phone = st.text_input("Phone", key="add_phone")
        password = st.text_input("Password", type="password", key="add_password")
        is_admin = st.checkbox("Is Admin?", key="add_is_admin")
        if st.button("Add User"):
            if not validate_cnic(cnic):
                st.error("CNIC must be 13-15 digits")
                return
            if not validate_phone(phone):
                st.error("Phone must be 11 digits")
                return
            try:
                response = requests.post(f"{BASE_URL}/admin/users", headers=headers, json={
                    "name": name,
                    "cnic": cnic,
                    "email": email,
                    "phone": phone,
                    "password": password,
                    "is_admin": is_admin
                })
                if response.status_code == 200:
                    st.success("User added successfully!")
                else:
                    st.error(response.json().get("detail", "Add user failed"))
            except requests.RequestException as e:
                st.error(f"Failed to connect to the server: {e}")
    elif menu == "Edit User":
        st.subheader("Edit User")
        user_id = st.number_input("User ID to Edit", min_value=1, step=1, key="edit_user_id")
        name = st.text_input("New Name (optional)", key="edit_name")
        email = st.text_input("New Email (optional)", key="edit_email")
        phone = st.text_input("New Phone (optional)", key="edit_phone")
        password = st.text_input("New Password (optional)", type="password", key="edit_password")
        is_admin = st.checkbox("Is Admin?", key="edit_is_admin")
        if st.button("Update User"):
            data = {}
            if name: data["name"] = name
            if email: data["email"] = email
            if phone: data["phone"] = phone
            if password: data["password"] = password
            data["is_admin"] = is_admin
            try:
                response = requests.put(f"{BASE_URL}/admin/users/{user_id}", headers=headers, json=data)
                if response.status_code == 200:
                    st.success("User updated successfully!")
                else:
                    st.error(response.json().get("detail", "Update failed"))
            except requests.RequestException as e:
                st.error(f"Failed to connect to the server: {e}")
    elif menu == "Delete User":
        st.subheader("Delete User")
        user_id = st.number_input("User ID to Delete", min_value=1, step=1, key="delete_user_id")
        if st.button("Delete User"):
            try:
                response = requests.delete(f"{BASE_URL}/admin/users/{user_id}", headers=headers)
                if response.status_code == 204:
                    st.success("User deleted successfully!")
                else:
                    st.error(response.json().get("detail", "Delete failed"))
            except requests.RequestException as e:
                st.error(f"Failed to connect to the server: {e}")
    elif menu == "Logout":
        st.session_state.clear()
        st.success("Logged out successfully!")
        st.experimental_rerun()

def user_dashboard():
    st.sidebar.title("Menu")
    option = st.sidebar.radio("Select Option", ["My Profile", "Update Profile", "Delete Profile", "Logout"])
    if option == "My Profile":
        # Show the logged-in user's profile
        headers = {"Authorization": f"Bearer {st.session_state.token}"}
        user_id = st.session_state.get("user_id")
        if user_id:
            try:
                response = requests.get(f"{BASE_URL}/users/{user_id}", headers=headers)
                if response.status_code == 200:
                    user = response.json()
                    st.write(f"Name: {user['name']}")
                    st.write(f"CNIC: {user['cnic']}")
                    st.write(f"Email: {user['email']}")
                    st.write(f"Phone: {user['phone']}")
                    st.write(f"Created At: {user['created_at']}")
                else:
                    st.error(response.json().get("detail", "Error fetching user"))
            except requests.RequestException as e:
                st.error(f"Failed to connect to the server: {e}")
        else:
            st.error("User ID not found in session. Please log in again.")
    elif option == "Update Profile":
        update_profile()
    elif option == "Delete Profile":
        delete_profile()
    elif option == "Logout":
        st.session_state.clear()
        st.success("Logged out successfully!")
        st.experimental_rerun()

def main():
    st.title("Online Identity Verification System")
    if "token" not in st.session_state:
        # Show login, register, and admin login options on initial load
        option = st.radio("Select Option", ["Login", "Register", "Admin Login"])
        if option == "Login":
            login()
        elif option == "Register":
            register()
        elif option == "Admin Login":
            admin_login()
    else:
        # Check if admin
        if st.session_state.get("is_admin"):
            admin_dashboard()
        else:
            user_dashboard()

if __name__ == "__main__":
    main()