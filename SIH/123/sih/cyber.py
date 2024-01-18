from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import psutil
import smtplib
import os
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Dummy data for servers and firewall rules
servers = [
    {"server_name": "Server1", "status": "Online", "ip": "192.168.1.1"},
    {"server_name": "Server2", "status": "Offline", "ip": "192.168.1.2"},
]

software_licenses_admin = [
    {"license_key": "ABC123", "software_name": "Software A", "expiration_date": "2023-12-31", "seats": 10},
    {"license_key": "XYZ456", "software_name": "Software B", "expiration_date": "2024-06-30", "seats": 5},
]

# Updated firewall_rules data structure with rule_id
firewall_rules = [
    {"rule_id": 2, "source_ip": "10.0.0.0/24", "action": "Deny"},
    {"rule_id": 1, "source_ip": "192.168.1.0/24", "action": "Allow"},
]

# Dummy data for user accounts (for demonstration purposes)
users = [
    {"username": "admin", "password": generate_password_hash("admin_password"), "role": "admin"},
    {"username": "user", "password": generate_password_hash("user_password"), "role": "user"},
]

# Sample data for load balancers (replace with your actual data)
load_balancers = [
    {"name": "LB1", "ip": "192.168.1.100", "status": "Active"},
    {"name": "LB2", "ip": "192.168.1.101", "status": "Active"},
]


@app.route('/')
def index():
    if 'username' in session:
        if 'license_accepted' in session:
            return render_template('add_details.html', user=get_user())
        else:
            return redirect(url_for('license_prompt'))
    else:
        return redirect(url_for('cyber'))  # Redirect to 'cyber.html' route

@app.route('/cyber')
def cyber():
    return render_template('cyber.html')

    

@app.route('/license_prompt')
def license_prompt():
    if 'license_accepted' in session:
        # The license has already been accepted, redirect to the main content.
        return redirect(url_for('index'))
    return render_template('license_prompt.html')

@app.route('/accept_license', methods=['POST'])
def accept_license():
    session['license_accepted'] = True
    flash('License accepted!', 'success')
    return redirect(url_for('index'))


@app.route('/main_login', methods=['GET', 'POST'])
def main_login():
    if request.method == 'POST':
        if 'admin_login' in request.form:  # Check if it's an admin login
            admin_username = request.form['admin_username']
            admin_password = request.form['admin_password']

            admin = next((u for u in users if u['username'] == admin_username and u['role'] == 'admin'), None)
            if admin and check_password_hash(admin['password'], admin_password):
                session['username'] = admin_username
                flash('Admin logged in successfully', 'success')
                return redirect(url_for('index'))
            else:
                flash('Admin login failed. Please check your username and password.', 'danger')
        else:  # Regular user login
            username = request.form['username']
            password = request.form['password']

            user = next((u for u in users if u['username'] == username), None)
            if user and check_password_hash(user['password'], password):
                session['username'] = username
                flash('User logged in successfully', 'success')
                return redirect(url_for('index'))
            else:
                flash('User login failed. Please check your username and password.', 'danger')

    return render_template('main_login.html')

# Add a new route for user registration
@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        register_username = request.form['register_username']
        register_password = request.form['register_password']

        # Check if the username is already taken
        if any(u['username'] == register_username for u in users):
            flash('Username is already taken. Please choose another username.', 'danger')
        else:
            # Create a new user account
            users.append({"username": register_username, "password": generate_password_hash(register_password), "role": "user"})
            flash('User registered successfully. You can now log in.', 'success')

    return redirect(url_for('main_login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('main_login'))




@app.route('/licence')
def licence():
    return render_template('licence.html')



@app.route('/server_details')
def server_details():
    user = get_user()
    return render_template('details.html', details=servers, type='Server', user=user)

@app.route('/firewall_details')
def firewall_details():
    user = get_user()
    sorted_firewall_rules = sorted(firewall_rules, key=lambda x: x['rule_id'])
    return render_template('details.html', details=sorted_firewall_rules, type='Firewall Rule', user=user)
# Route for adding a server (only accessible to admin users)
@app.route('/add_server', methods=['POST'])
def add_server():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            if request.method == 'POST':
                server_name = request.form['server_name']
                status = request.form['status']
                ip = request.form['ip']

                # Insert the new server into the servers list (replace this with your data storage logic)
                new_server = {
                    'server_name': server_name,
                    'status': status,
                    'ip': ip
                }
                servers.append(new_server)

                flash(f'Server {server_name} has been added successfully', 'success')

            return redirect(url_for('index'))
        else:
            flash('Access denied. You do not have permission to add details.', 'danger')
    else:
        return redirect(url_for('main_login'))



# Route to delete a server (only accessible to admin users)
@app.route('/delete_server/<int:server_index>', methods=['POST'])
def delete_server(server_index):
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            try:
                # Check if the server_index is valid
                if 0 <= server_index < len(servers):
                    # Delete the server entry from the servers list
                    deleted_server = servers.pop(server_index)
                    flash(f'Server {deleted_server["name"]} has been deleted successfully', 'success')
                else:
                    flash('Invalid server index', 'danger')
            except Exception as e:
                flash(f'An error occurred: {str(e)}', 'danger')
            return redirect(url_for('server_details'))
        else:
            flash('Access denied. You do not have permission to delete details.', 'danger')
            return redirect(url_for('server_details'))
    else:
        return redirect(url_for('main_login'))


# Route for adding a firewall rule (only accessible to admin users)
@app.route('/add_firewall_rule', methods=['POST'])
def add_firewall_rule():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            if request.method == 'POST':
                source_ip = request.form['source_ip']
                action = request.form['action']

                # Calculate the new rule_id based on the current length of the firewall_rules list
                new_rule_id = len(firewall_rules) + 1

                # Insert the new firewall rule with the updated rule_id
                new_firewall_rule = {"rule_id": new_rule_id, "source_ip": source_ip, "action": action}
                firewall_rules.append(new_firewall_rule)

                flash(f'Firewall rule {new_rule_id} has been added successfully', 'success')

            return redirect(url_for('index'))
        else:
            flash('Access denied. You do not have permission to add details.', 'danger')
    else:
        return redirect(url_for('main_login'))

# Route for deleting a firewall rule (only accessible to admin users)
@app.route('/delete_firewall_rule/<int:rule_id>', methods=['POST'])
def delete_firewall_rule(rule_id):
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            if request.method == 'POST':
                rule_to_delete = next((rule for rule in firewall_rules if rule['rule_id'] == rule_id), None)
                if rule_to_delete:
                    firewall_rules.remove(rule_to_delete)

                # Reassign rule_ids to maintain ascending order
                for index, rule in enumerate(firewall_rules):
                    rule['rule_id'] = index + 1

            return redirect(url_for('firewall_details'))
        else:
            flash('Access denied. You do not have permission to delete firewall rules.', 'danger')
    else:
        return redirect(url_for('main_login'))
# Helper function to get the currently logged-in user
def get_user():
    if 'username' in session:
        username = session['username']
        user = next((u for u in users if u['username'] == username), None)
        return user
    return None
# Create a list to store provisioning requests
provisioning_requests = []

# Modify the /server_provisioning route to handle form submission
@app.route('/server_provisioning', methods=['GET', 'POST'])
def server_provisioning():
    if 'username' in session:
        user = get_user()
        if user:
            if request.method == 'POST':
                # Handle the form submission here
                server_name = request.form.get('server_name')

                # Perform any necessary processing and update the provisioning_requests list
                # For example, you can append a new request to the list
                provisioning_requests.append({
                    'requester': user['username'],
                    'server_name': server_name,
                    'status': 'Pending',  # Set the initial status as "Pending"
                    'id': len(provisioning_requests) + 1  # Assign a unique ID to the request
                })

                flash(f'Server provisioning request for "{server_name}" submitted successfully', 'success')

            return render_template('server_provisioning.html')
        else:
            flash('Please log in to submit a server provisioning request.', 'danger')
            return redirect(url_for('main_login'))
    else:
        return redirect(url_for('main_login'))

# Create a new route for admin to view provisioning requests
@app.route('/server_provisioning_requests')
def server_provisioning_requests():
    if 'username' in session:
        user = get_user()
        if user and user['role'] == 'admin':
            return render_template('server_provisioning_requests.html', provisioning_requests=provisioning_requests)
        else:
            flash('Access denied. You do not have permission to view provisioning requests.', 'danger')
            return redirect(url_for('index'))
    else:
        flash('Please log in as an admin to view provisioning requests.', 'danger')
        return redirect(url_for('main_login'))

@app.route('/approve_request/<int:request_id>', methods=['POST'])
def approve_request(request_id):
    # Find the request in the data structure by ID and update its status
    request_to_approve = next((request for request in provisioning_requests if request['id'] == request_id), None)
    if request_to_approve:
        request_to_approve['status'] = 'Approved'
        # You can perform additional actions here, such as server provisioning

    return redirect(url_for('server_provisioning_requests'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    # Find the request in the data structure by ID and update its status
    request_to_reject = next((request for request in provisioning_requests if request['id'] == request_id), None)
    if request_to_reject:
        request_to_reject['status'] = 'Rejected'
        # You can perform additional actions here, such as notifying the requester

    return redirect(url_for('server_provisioning_requests'))

@app.route('/hardware_inventory')
def hardware_inventory():
    user = get_user()
    if user and user['role'] == 'admin':
        # Add any necessary data or logic for the hardware inventory page here
        return render_template('hardware_inventory.html')  # Render the HTML page
    else:
        flash('Access denied. You do not have permission to access hardware inventory.', 'danger')
        return redirect(url_for('index'))


# Initialize a list to store hardware inventory data
hardware_inventory = []

@app.route('/add_hardware', methods=['POST'])
def add_hardware():
    if request.method == 'POST':
        hardware_name = request.form.get('hardware_name')
        status = request.form.get('hardware_status')
        warranty_expiry_date = request.form.get('hardware_warranty')
        next_maintenance_date = request.form.get('hardware_maintenance')

        # Create a dictionary to store the hardware inventory data
        hardware_item = {
            'name': hardware_name,
            'status': status,
            'warranty_expiry_date': warranty_expiry_date,
            'next_maintenance_date': next_maintenance_date
        }

        # Append the hardware item to the hardware_inventory list
        hardware_inventory.append(hardware_item)

    return redirect('/hardware_details')

@app.route('/hardware_details')
def hardware_details():
    return render_template('hardware_details.html', hardware_inventory=hardware_inventory)
# Create a Flask route for deleting hardware inventory
@app.route('/delete_hardware', methods=['POST'])
def delete_hardware():
    if request.method == 'POST':
        hardware_name_to_delete = request.form.get('hardware_name')

        # Find and remove the hardware item from the hardware_inventory list
        for item in hardware_inventory:
            if item['name'] == hardware_name_to_delete:
                hardware_inventory.remove(item)
                break  # Exit the loop after deleting the item

    return redirect('/hardware_details')

@app.route('/reporting_page')
def reporting_page():
    # You can pass any data you want to the template here
    return render_template('reporting.html')


cpu_data = []

def generate_cpu_data():
    return random.randint(0, 100)

@app.route('/monitoring_dashboard')
def monitoring_dashboard():
    return render_template('monitoring_dashboard.html')


# Simulated monitoring data (replace with your actual data source)
monitoring_data = {
    "cpuUsage": 65.43,
    "memoryUsage": 42.18
}

@app.route('/api/get_monitoring_data', methods=['GET'])
def get_monitoring_data():
    return jsonify(monitoring_data)
    

# Route to the Load Balancer Management page
@app.route('/load', methods=['GET', 'POST'])
def load_balancer_management():
    if request.method == 'POST':
        action = request.form['action']
        lb_name = request.form['lb_name']
        ip = request.form['ip']

        if action == 'add':
            # Add the load balancer details to the list
            load_balancers.append({
                'name': lb_name,
                'ip': ip,
                'status': 'Active'  # You can set the initial status as needed
            })
        elif action == 'remove':
            # Remove the load balancer with the specified name
            for lb in load_balancers:
                if lb['name'] == lb_name:
                    load_balancers.remove(lb)

    return render_template('load_balancer_management.html', user={'username': 'Admin'}, load_balancers=load_balancers)

if __name__ == '__main__':
    app.run(debug=True)
