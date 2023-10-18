from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

# Remove all past jobs
scheduler.remove_all_jobs()


def my_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            if user.is_staff != True:
                return redirect('/admin')
            else:
                return redirect('/my-page')
        else:
            return render(request, 'login.html', {'error_message': 'Invalid login'})
    return render(request, 'login.html')



from django.shortcuts import render
from django.contrib.auth.decorators import login_required

def hello_world_view(request):
    return render(request, 'hello_world.html',{'user': request.user})

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages

#def registration_view(request):
#    if request.method == 'POST':
#        form = UserCreationForm(request.POST)
#        if form.is_valid():
#            user = form.save()
#            login(request, user)
#            messages.success(request, 'Registration successful. Redirecting to login page...')
#            return render(request, 'registration.html', {'form': form, 'success': True})
#        else:
#            messages.error(request, 'Username already exists. Please choose another username.')
#    else:
#        form = UserCreationForm()
#    return render(request, 'registration.html', {'form': form})
#
from .forms import CustomUserCreationForm
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import CustomUserCreationForm
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.shortcuts import render
from django.contrib import messages
from .forms import CustomUserCreationForm
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from .forms import CustomUserCreationForm

def registration_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_staff = True
            user.save()
            username = form.cleaned_data.get('username')
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            messages.success(request, 'Registration successful. You have been logged in.')
            return redirect('login')
        else:
            messages.error(request, 'Registration unsuccessful. Please try again.')
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration.html', {'form': form})


from django.contrib.auth import logout

def logout_view(request):
    request.session.clear()
    return redirect('login')


from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView
from django.shortcuts import render, redirect

from django.shortcuts import render

from django.contrib.auth.decorators import login_required

@login_required(login_url='/login/')
def my_view(request):
    virtual_machines = VM.objects.all()
    return render(request, 'usertemplate.html', {'virtual_machines': virtual_machines})


from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages

@csrf_protect
@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, request.user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('change_password_done')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'upwd.html', {'form': form})



from django.shortcuts import render, redirect
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy


from django.shortcuts import render
from django.shortcuts import render
from .models import VM
from django.contrib.auth.decorators import login_required
from datetime import datetime, timedelta

from django.db.models import F

import stripe


@login_required
def visuals(request):
    # Retrieve the VM objects of the current user from the database
    vms = VM.objects.filter(user=request.user.username, payed=True)
    # Pass the VM objects to the template
    return render(request, 'visuals.html', {'vms': vms})

import stripe
from django.conf import settings
from django.shortcuts import render
from .models import VM

import stripe

import stripe
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import VM
from .forms import PaymentForm

stripe.api_key = 'sk_test_51MeMiQHmsJXykv8f973lWHHgY37Cx2q3chulZEmC0OTi3oDMXO4kJT9EtQ00VoNfWbybNZVnvKRhGt7IpohjNpgi00t650k46e'
from django.urls import reverse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# views.py
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import VM
from django.utils import timezone

import stripe

stripe.api_key = settings.STRIPE_SECRET_KEY

@login_required
def create_vm(request):
    if request.method == 'POST':
        os = request.POST.getlist('os')
        cpu = int(request.POST['cpu'])
        ram = int(request.POST['ram'])
        rom = int(request.POST['rom'])
        packages = request.POST.getlist('packages')
        sub = int(request.POST['sub'])

        total = sub*(cpu*100 + ram*100 + rom+100 + len(packages)*100)
        fbill = (cpu*100 + ram*100 + rom+100 + len(packages)*100)

        if 'save' in request.POST:
            vm = VM(
                os=os,
                cpu=cpu,
                ram=ram,
                rom=rom,
                packages=','.join(packages),
                total=total,
                user=request.user.username,
                payed=False,
                status=False,             
                creation_date=timezone.now(),
                expiration_date=timezone.now() + timedelta(days=30*sub),
                fbill=fbill
            )
            vm.save()

            # Create a Checkout Session with Stripe
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'unit_amount': total,
                        'product_data': {
                            'name': 'Virtual Machine',
                        },
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=request.build_absolute_uri('/createvm/success/') + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=request.build_absolute_uri('/createvm/cancel/'),
                metadata={
                    'vm_id': vm.id,
                },               
            )

            # Redirect to the Checkout Session
            return redirect(checkout_session.url)

        # If 'calculate' was clicked, just return the total without saving the VM object
        elif 'calculate' in request.POST:
            return render(request, 'createvm.html', {'total': total})

    # If the request method was not POST, just render the empty form
    else:
        return render(request, 'createvm.html')
        
    return render(request, 'createvm.html')



def cancel(request):
    return render(request, 'payf.html')




from django.shortcuts import render
from django.shortcuts import render
from .models import VM
from django.contrib.auth.decorators import login_required
from datetime import datetime, timedelta

from django.db.models import F

import copy

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.utils import timezone
from datetime import timedelta
import copy
import stripe
import time
from .models import VM
from django.http import Http404

import subprocess
import threading

def stop_and_delete_vm(vm_id):
    # Stop the VM
    subprocess.run(["virtctl", "stop", vm_id])

    # Wait for 7 seconds
    time.sleep(10)

    # Delete the VM
    subprocess.run(["minikube","kubectl","--", "delete", "vm", vm_id])

    # Wait for 1 second
    time.sleep(2)

    # Delete the PVC
    subprocess.run(["minikube","kubectl","--", "delete", "pvc", vm_id])




import webbrowser

def start_and_vnc(vm_id):
    # Start the VM
    subprocess.run(["virtctl", "start", vm_id])

    # Wait for 10 seconds
    time.sleep(10)

    # Retrieve the VNC URL
    url = subprocess.check_output(["minikube", "service", "virtvnc", "-n", "kubevirt", "--url"]).decode().strip()
    time.sleep(5)
    # Append the rest of the URL and replace the VM ID
    url += "/vnc_lite.html?path=k8s/apis/subresources.kubevirt.io/v1alpha3/namespaces/default/virtualmachineinstances/{}/vnc".format(vm_id)

    # Open the URL in a new tab
    webbrowser.open_new_tab(url)

def stop_vm(vm_id):
    # Start the VM
    subprocess.run(["virtctl", "stop", vm_id])
    vm = VM.objects.get(id=vm_id)
    vm.vm_name = "N/A"
    vm.save()


@login_required
def managevm(request):
    # Retrieve the VM objects of the current user from the database
    vms = VM.objects.filter(user=request.user.username, payed=True)

    if request.method == 'POST':
        # Handle form submission
        if 'update_vm' in request.POST:
            # Update an existing VM
            vm_id = request.POST['vm_id']
            cpu = int(request.POST['cpu'])
            ram = int(request.POST['ram'])
            payed = 'payed' in request.POST
            sub = int(request.POST['sub'])

            # Retrieve the VM object and update its properties
            vm = VM.objects.get(id=vm_id)

            # Calculate the updated total value based on the old total value and the added CPU, RAM, ROM, and packages
            old_fbill = int(vm.fbill)
            how = old_fbill - old_fbill

            if cpu > vm.cpu:
                vm.fbill += (cpu - vm.cpu) * 100
                vm.cpu = cpu
            if ram > vm.ram:
                vm.fbill += (ram - vm.ram) * 100
                vm.ram = ram

            if sub == 0:
                how = vm.fbill - old_fbill
            
            elif sub != 0:
                how = vm.fbill * sub 
                
            # Update the expiration date based on the number of months the user has subscribed for
            vm.expiration_date = vm.expiration_date + timedelta(days=30*sub)

            # Redirect the user to the Stripe checkout page to pay the difference in cost, if any
            if how > 0 :
                checkout_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{
                        'price_data': {
                            'currency': 'usd',
                            'unit_amount': (how),
                            'product_data': {
                                'name': 'Virtual Machine Upgrade',
                            },
                        },
                        'quantity': 1,
                    }],
                    mode='payment',
                    success_url=request.build_absolute_uri('/managevm/success/') + '?session_id={CHECKOUT_SESSION_ID}',
                    cancel_url=request.build_absolute_uri('/managevm/cancel/'),
                    metadata={
                        'vm_id': vm.id,
                        'cpu': cpu,
                        'ram': ram,
                        'sub': sub,
                    },    
                )
                return redirect(checkout_session.url)

        elif 'delete_vm' in request.POST:
            # Delete an existing VM object
            vm_id = request.POST.get('vm_id')
            vm = VM.objects.get(pk=vm_id)
            vm.delete()
            
            # Start a new thread to stop and delete the VM
            t = threading.Thread(target=stop_and_delete_vm, args=(vm_id,))
            t.start()

            # Redirect the user to the VM management page
            return redirect('managevm')
        
        elif 'start_vm_view' in request.POST:
            # Delete an existing VM object
            vm_id = request.POST.get('vm_id')
            vm = VM.objects.get(pk=vm_id)
            
            # Start a new thread to stop and delete the VM
            s = threading.Thread(target=start_and_vnc, args=(vm_id,))
            s.start()

            # Redirect the user to the VM management page
        elif 'stop_vm_view' in request.POST:
            # Delete an existing VM object
            vm_id = request.POST.get('vm_id')
            vm = VM.objects.get(pk=vm_id)
            
            # Start a new thread to stop and delete the VM
            p = threading.Thread(target=stop_vm, args=(vm_id,))
            p.start()


            # Redirect the user to the VM management page
            return redirect('managevm')

    # Pass the VM objects to the template
    return render(request, 'managevm.html', {'vms': vms})




#def msucceess(request):
#    return render(request, 'pays.html')

import json

def msucceess(request):
    session_id = request.GET['session_id']
    checkout_session = stripe.checkout.Session.retrieve(session_id)

    # Get the VM ID from the checkout session metadata
    vm_id = checkout_session.metadata['vm_id']

    # Retrieve the VM object and update its properties
    vm = VM.objects.get(id=vm_id)

    # Retrieve the new values from the checkout session metadata
    cpu = int(checkout_session.metadata['cpu'])
    ram = int(checkout_session.metadata['ram'])
    sub = int(checkout_session.metadata['sub'])

    # Calculate the updated total value based on the old total value and the added CPU, RAM, ROM, and packages
    old_fbill = int(vm.fbill)
    how = old_fbill - old_fbill

    if cpu > vm.cpu:
        vm.fbill += (cpu - vm.cpu) * 100
        vm.cpu = cpu
    if ram > vm.ram:
        vm.fbill += (ram - vm.ram) * 100
        vm.ram = ram

    if sub == 0:
        vm.total += vm.fbill - old_fbill
    
    elif sub != 0:
        vm.total += vm.fbill * sub 
    # Update the expiration date based on the number of months the user has subscribed for
    vm.expiration_date = vm.expiration_date + timedelta(days=30*sub)

    vm.save()
    
    # Call the appropriate function based on the VM OS
    if "ubuntu" in vm.os:
        print("verif",(vm_id))
        subprocess.run(["virtctl", "stop", vm_id])

        # Wait for 7 seconds
        time.sleep(8)

        #Delete the VM
        subprocess.run(["minikube","kubectl","--", "delete", "vm", vm_id])

        #Wait for 1 second
        time.sleep(2)    
        createubuntu(vm_id)

    elif "windows" in vm.os:
        print("verif",(vm_id))
        subprocess.run(["virtctl", "stop", vm_id])

        # Wait for 7 seconds
        time.sleep(8)

        #Delete the VM
        subprocess.run(["minikube","kubectl","--", "delete", "vm", vm_id])

        #Wait for 1 second
        time.sleep(2) 
        createwindows(vm_id)
    

    # Redirect the user to the VM management page
    return render(request, 'pays.html')


from django.utils import timezone
from .models import VM

from apscheduler.schedulers.background import BackgroundScheduler
from django.utils import timezone
from .models import VM

def delete_unpaid_vms():
    """
    This function deletes unpaid VMs that have been alive for more than 5 minutes.
    """
    five_minutes_ago = timezone.now() - timezone.timedelta(minutes=5)
    unpaid_vms = VM.objects.filter(payed=False, creation_date__lte=five_minutes_ago)
    deleted_count, _ = unpaid_vms.delete()
    message = f"Deleted {deleted_count} VMs that were unpaid and alive for more than 5 minutes."
    print(message) # Print to console for debugging purposes

# Create a scheduler and add the function to run every 5 minutes
scheduler = BackgroundScheduler()
scheduler.add_job(delete_unpaid_vms, 'interval', minutes=5)
scheduler.start()



@login_required
def success(request):
    session_id = request.GET.get('session_id')
    checkout_session = stripe.checkout.Session.retrieve(session_id)

    # Get the VM ID from the checkout session metadata
    vm_id = checkout_session.metadata['vm_id']
    idd=vm_id 
    print("check1",(idd))
    vm = VM.objects.get(id=vm_id)

    
    if checkout_session.payment_status == 'paid':

        # Retrieve the VM object and update its properties

        vm.payed = True
        vm.ip = "na"
        vm.save()

        # Call the appropriate function based on the VM OS
    if "ubuntu" in vm.os:
        print("verif",(idd))
        createubuntu(idd)

    elif "windows" in vm.os:
        createwindows(idd)

    return render(request, 'vv.html')



import subprocess
import yaml
import os


def createwindows(idd):
    # Retrieve the VM object from the database
    print("Creating Ubuntu VM with ID:", idd)
    vm = VM.objects.get(id=idd)

    # Check if the PVC already exists
    pvc_name = idd
    pvc_exists = subprocess.run(["minikube","kubectl","--", "get", "pvc", pvc_name], capture_output=True).returncode == 0

    # Create the PVC if it doesn't exist
    if not pvc_exists:
  # Load the base PVC YAML file into a Python object
        with open("pvc_manifest2.yaml", "r") as f:
            pvc_manifest = yaml.safe_load(f)

        # Update the appropriate fields
        pvc_manifest["metadata"]["name"] = vm.id
        pvc_manifest["spec"]["resources"]["requests"]["storage"] = str(vm.rom) + "Gi"

        # Convert the dictionary to a YAML string
        pvc_manifest_yaml = yaml.dump(pvc_manifest)

        # Apply the updated PVC YAML file using kubectl
        subprocess.run(["minikube","kubectl","--", "apply", "-f", "-"], input=pvc_manifest_yaml.encode("utf-8"))

        print("PVC created.")

        # Wait for 180 seconds for the PVC to be created
        print("Waiting for PVC to be created...")
        time.sleep(30)

        
        
    # Check if the VM already exists
    vm_name = idd
    vm_exists = subprocess.run(["minikube","kubectl","--", "get", "vm", vm_name], capture_output=True).returncode == 0

    # Create the VM if it doesn't exist
    if not vm_exists:
        # Load the YAML file into a Python object
        with open("vm_manifest2.yaml", "r") as f:
            vm_manifest = yaml.safe_load(f)

        # Update the appropriate fields
        vm_manifest["metadata"]["name"] = idd        
        vm_manifest["spec"]["template"]["metadata"]["labels"]["kubevirt.io/domain"] = idd
        vm_manifest["spec"]["template"]["spec"]["domain"]["cpu"]["cores"] = vm.cpu    
        vm_manifest["spec"]["template"]["spec"]["domain"]["resources"]["requests"]["memory"] = str(vm.ram) + "G"
        
        vm_manifest["spec"]["template"]["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] = vm.id

        # Write the updated object back to the file
        # Convert the dictionary to a YAML string
        vm_manifest_yaml = yaml.dump(vm_manifest)

        # Run the kubectl command with the YAML string as input
        subprocess.run(["minikube","kubectl","--", "apply", "-f", "-"], input=vm_manifest_yaml.encode("utf-8"))


def createubuntu(idd):
    # Retrieve the VM object from the database
    print("Creating Ubuntu VM with ID:", idd)
    vm = VM.objects.get(id=idd)

    # Check if the PVC already exists
    pvc_name = idd
    pvc_exists = subprocess.run(["minikube","kubectl","--", "get", "pvc", pvc_name], capture_output=True).returncode == 0

    # Create the PVC if it doesn't exist
    if not pvc_exists:
  # Load the base PVC YAML file into a Python object
        with open("pvc_manifest.yaml", "r") as f:
            pvc_manifest = yaml.safe_load(f)

        # Update the appropriate fields
        pvc_manifest["metadata"]["name"] = vm.id
        pvc_manifest["spec"]["resources"]["requests"]["storage"] = str(vm.rom) + "Gi"

        # Convert the dictionary to a YAML string
        pvc_manifest_yaml = yaml.dump(pvc_manifest)

        # Apply the updated PVC YAML file using kubectl
        subprocess.run(["minikube","kubectl","--", "apply", "-f", "-"], input=pvc_manifest_yaml.encode("utf-8"))

        print("PVC created.")

        # Wait for 180 seconds for the PVC to be created
        print("Waiting for PVC to be created...")
        time.sleep(30)

        
        
    # Check if the VM already exists
    vm_name = idd
    vm_exists = subprocess.run(["minikube","kubectl","--", "get", "vm", vm_name], capture_output=True).returncode == 0

    # Create the VM if it doesn't exist
    if not vm_exists:
        # Load the YAML file into a Python object
        with open("vm_manifest.yaml", "r") as f:
            vm_manifest = yaml.safe_load(f)

        # Update the appropriate fields
        vm_manifest["metadata"]["labels"]["kubevirt.io/vm"] = idd
        vm_manifest["metadata"]["name"] = idd
        vm_manifest["spec"]["template"]["metadata"]["labels"]["kubevirt.io/vm"] = idd
        vm_manifest["spec"]["template"]["spec"]["domain"]["resources"]["requests"]["memory"] = str(vm.ram) + "G"
        vm_manifest["spec"]["template"]["spec"]["domain"]["resources"]["requests"]["cpu"] = vm.cpu
        vm_manifest["spec"]["template"]["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] = vm.id

        # Write the updated object back to the file
        # Convert the dictionary to a YAML string
        vm_manifest_yaml = yaml.dump(vm_manifest)

        # Run the kubectl command with the YAML string as input
        subprocess.run(["minikube","kubectl","--", "apply", "-f", "-"], input=vm_manifest_yaml.encode("utf-8"))
        
        
        
        
        
        
        
import subprocess
import webbrowser

def launch_dashboard(request):
    
    result = subprocess.run(["minikube", "dashboard"], stdout=subprocess.PIPE)
    print(result.stdout)

    return redirect('/my-page/')



import subprocess
import re

import subprocess
import re
#result = subprocess.run(["minikube","kubectl", "--", "top", "pods", "-n", "default"], capture_output=True, text=True)



import subprocess
import re


def update_vm_metrics():
    result = subprocess.run(["minikube", "kubectl", "--", "top", "pods", "-n", "default"], capture_output=True, text=True)
    output = result.stdout.strip()

    # Iterate over each line of the command output
    for line in output.split('\n')[1:]:
        columns = re.split(r'\s+', line.strip())
        if len(columns) >= 3:
            current_pod = columns[0]
            cpu_usage = columns[1]
            memory_usage = columns[2]
            
            vms = VM.objects.all()
            for vm in vms:
                # Check if the pod name matches the desired name
                if vm.id in current_pod:
                    vm.vm_name = f"mCPU cores: {cpu_usage} Memory bytes: {memory_usage}"
                    vm.save()

scheduler = BackgroundScheduler()
scheduler.add_job(update_vm_metrics, 'interval', seconds=60)
scheduler.start()



import subprocess
import time

def update_vm_status():
    result = subprocess.run(["minikube","kubectl","--", "get", "vm"], capture_output=True, text=True)
    output = result.stdout.strip()

    vm_lines = output.split('\n')[1:]
    for line in vm_lines:
        columns = line.split()
        if len(columns) >= 4:
            vmname = columns[0]
            status = columns[2]

            # Find the VM with the matching name in the database
            try:
                vm = VM.objects.get(id=vmname)
                vm.status = True if status.lower() == 'running' else False
                vm.vm_name = vm.vm_name if vm.status else "N/A"
                vm.save()
            except VM.DoesNotExist:
                # Handle case when VM is not found in the database
                pass

scheduler = BackgroundScheduler()
scheduler.add_job(update_vm_status, 'interval', seconds=60)
scheduler.start()




import cv2
import numpy as np
import torch
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt




from django.shortcuts import render

# Rest of the code...

def detect_objects(request):

        return render(request, 'results.html')  # Render the 'results.html' template

    # Rest of the code...


import subprocess
import os


def process_live_data():
    # Specify the file path
    file_path = "output.csv"

    # Check if the file exists
    if os.path.exists(file_path):
        # Delete the file
        os.remove(file_path)
        print("File deleted successfully.")
    else:
        print("File does not exist.")
    # Run argus command and capture output to a CSV file
    command = "echo 'ubuntu' | sudo -S argus -i wlo1 -w - | ra -s saddr,sport,daddr,dport,dload,spkts,sbytes,dloss,dbytes,smeansz,sload,dmeansz,rate -c , -u - > output.csv"
    subprocess.Popen(command, shell=True)


process_live_data()


import pandas as pd
import schedule
import time
import subprocess
from pycaret.classification import load_model, predict_model
loaded = load_model('my_first_model')



def process_output_csv():
    while True:
        try:
            # Read the output.csv file
            df = pd.read_csv('output.csv')
            
            # Calculate ct_dst_sport_ltm
            df['ct_dst_sport_ltm'] = df.groupby(['DstAddr', 'Sport'])['SrcAddr'].transform('nunique')
            
            # Reindex the columns
            desired_columns = ['ct_dst_sport_ltm', 'DstLoad', 'SrcPkts', 'SrcBytes', 'DstLoss', 'DstBytes',
                               'sMeanPktSz', 'SrcLoad', 'dMeanPktSz', 'Rate', 'SrcAddr', 'Sport', 'DstAddr', 'Dport']
            df = df.reindex(columns=desired_columns)
            time.sleep(1)
            # Rename columns
            column_mapping = {
                'DstLoad': 'dload',
                'SrcPkts': 'spkts',
                'SrcBytes': 'sbytes',
                'DstLoss': 'dloss',
                'DstBytes': 'dbytes',
                'sMeanPktSz': 'smean',
                'SrcLoad': 'sload',
                'dMeanPktSz': 'dmean',
                'Rate': 'rate'
            }
            df.rename(columns=column_mapping, inplace=True)
            
            # Process the updated DataFrame
            process_dataframe(df)
            
        except FileNotFoundError:
            # If the file is not found, print an error message and continue
            print("output.csv file not found. Waiting for the file...")

from .models import VM



from .models import Messages

import csv

def process_dataframe(df):
    prediction_columns = ['ct_dst_sport_ltm', 'dload', 'spkts', 'sbytes', 'dloss', 'dbytes',
                          'smean', 'sload', 'dmean', 'rate']
    prediction_data = df[prediction_columns]
    unseen_predictions = predict_model(loaded, data=prediction_data)
    
    with open('output2.csv', 'a', newline='') as file:
        writer = csv.writer(file)
        
        for index, row in unseen_predictions.iterrows():
            if row['prediction_label'] == 1:
                display_columns = ['SrcAddr', 'Sport', 'DstAddr', 'Dport']
                display_data = df.loc[index, display_columns]
                src_addr = display_data['SrcAddr']
                src_port = display_data['Sport']
                dst_addr = display_data['DstAddr']
                dst_port = display_data['Dport']
                
                # Exclude anomalies where the source is localhost or local IP address
                if src_addr != '127.0.0.1' and not src_addr.startswith('192.168.'):
                    anomaly_info = f"Anomaly detected: Source {src_addr}:{src_port} Destination to {dst_addr}:{dst_port}"
                    
                    # Check if the anomaly information is already printed
                    if anomaly_info not in process_dataframe.previous_anomalies:
                        process_dataframe.previous_anomalies.add(anomaly_info)
                        
                        # Write anomaly information to the CSV file
                        writer.writerow([anomaly_info])

# Initialize a set to store the previously detected anomalies
process_dataframe.previous_anomalies = set()
time.sleep(10)

import threading

def start_processing_output_csv():
    # Call the function to start processing the output.csv file
    process_output_csv()

# Start the processing in a separate thread
processing_thread = threading.Thread(target=start_processing_output_csv)
processing_thread.start()



import csv
import io
from django.http import HttpResponse

import csv
import io
from django.http import HttpResponse
from django.http import HttpResponse

def get_output_csv(request):
    # Get the path to the output.csv file
    csv_path = 'output.csv'
    
    # Open the CSV file and read its contents
    with open(csv_path, 'r') as f:
        csv_data = f.read()
    
    # Return the CSV data as an HTTP response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="output.csv"'
    response.write(csv_data)
    return response

def get_output2_csv(request):
    # Get the path to the output.csv file
    csv_path = 'output2.csv'
    
    # Open the CSV file and read its contents
    with open(csv_path, 'r') as f:
        csv_data = f.read()
    
    # Return the CSV data as an HTTP response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="output2.csv"'
    response.write(csv_data)
    return response