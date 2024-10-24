#!/usr/bin/env python3
# Foundations of Python Network Programming, Third Edition
# https://github.com/brandon-rhodes/fopnp/blob/m/py3/chapter11/app_improved.py
# An application to request aphorisms from a server and display them onto an html.
#To initialise this program input python3 ./app_improved.py

import secrets
import random, socket, zen_utils, logging
from flask import (Flask, flash, get_flashed_messages,
                   redirect, render_template, request, session, url_for)
from markupsafe import escape
import ssl

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config.update(SESSION_COOKIE_SECURE=True)
app.config.update(SESSION_COOKIE_SAMESITE='Strict')
app.config.update(SESSION_COOKIE_HTTPONLY=True)

#init and config logger
logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s',
                     filename='csc2330a3app.log', encoding='utf-8',
level=logging.DEBUG)

#To initially redirect to the login page
@app.route('/', methods=['GET'])
def start():
    return redirect(url_for('login'))    
 

#To  test username and password before moving to the next webpage, 
#initiliase csrf token and process a log message.
@app.route('/login', methods=['GET', 'POST'])
def login():
    #escaping to reject code injection
    username = escape(request.form.get('username', ''))
    password = escape(request.form.get('password', ''))
    if request.method == 'POST':
        if (username, password) in [('u1130784', 'csc2330a3'), (
            'u1130784@umail.usq.edu.au', 't12024')]:
            session['username'] = username
            session['csrf_token'] = app.secret_key
            token1 = session['csrf_token']
            log_msg = ("Successful login by user" + username)
            logger.info(log_msg)
            return render_template('index.html', csrf_token = token1)
        else:
            flash('Invalid username or password provided', 'error')
            log_msg = ("Invalid username or password was used")
            logger.info(log_msg)   
    return render_template('login.html', username=username)


@app.route('/logout')
def logout():
    username = session.get('username')
    if not username:
        flash("Logout: Invalid Session")
        return redirect(url_for('login'))        
    session.clear()    
    return render_template('logout.html')
    

@app.route('/index', methods = ['GET', 'POST'])
def index():
    username = session.get('username')   
    token1 = request.form.get('csrf_token')    
    #check if the session is vaild
    if not username :
        flash("Index: Invalid session")
        return redirect(url_for('login'))  
    #To check for csrf token, otherwise redirect back to login       
    if request.form.get('csrf_token') != session['csrf_token']:
        flash("From Restricted POST No valid csrf token")
        return redirect(url_for('login'))
    return render_template('restricted.html', csrf_token=token1)
    

@app.route('/restricted', methods=['GET', 'POST'])
def restricted():
    username = session.get('username')
    #check if the session is vaild
    if not username :
        flash("Restricted GET:Invalid Session")
        return redirect(url_for('login'))    

    if request.method == 'POST' :
        #check if the session is vaild
        if not username:
            flash("Restricted POST: Invalid Session")
            return redirect(url_for("login"))
        #To check for csrf token, otherwise redirect back to login    
        if request.form.get('csrf_token') != session['csrf_token']:
            flash("From Restricted POST No valid csrf token")
            return redirect(url_for('login'))        
        
        #Establishing a secure connection to the backend server.    
        purpose = ssl.Purpose.SERVER_AUTH
        context = ssl.create_default_context(purpose, cafile='./keys/frontend.crt') 
        context.load_verify_locations(capath='./keys/')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE             
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(sock)
        ssl_sock.connect((socket.gethostname(), 1060))  
        #Preparing to request for aphorisms
        aphorisms = list(zen_utils.aphorisms)
        for aphorism in random.sample(aphorisms, 3):
            ssl_sock.sendall(aphorism)
            pre_aphor = aphorism, zen_utils.recv_until(ssl_sock,b'.')
        ssl_sock.close()
        #cleaning the aphorisms so that they are readable
        pre_aphor = str(pre_aphor)
        aphor = ""
        index = ["(",")","?"]
        for i in pre_aphor:
            if i not in index:
                aphor += i
        aphor = aphor.replace("b'", "").replace("',","").replace("'","")
        log_msg = ("Successful Delivery of aphorism")
        logger.info(log_msg)
        return render_template('del_of_aph.html', aphor=aphor)
   
    token = session['csrf_token']
    return render_template('rest_get.html', csrf_token = token)

if __name__ == '__main__':
    app.debug = True
    app.run(ssl_context=('./keys/www.crt', './keys/www.key'))
