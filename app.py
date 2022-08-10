import os
import sqlite3

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, usd


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route("/commodities", methods=["GET", "POST"])
@login_required
def commodities():
	db1 = sqlite3.connect("shopman.db")
	db2 = db1.cursor()
	current_user = session["user_id"]

	biz_det = db2.execute("SELECT * FROM business WHERE id =?", str(current_user))
	biz_det = biz_det.fetchall()

	if request.method == "GET":
		
		com_dets = db2.execute("SELECT * FROM commodities WHERE biz_id =?", str(current_user))
		com_dets = com_dets.fetchall()

		#print(isinstance(per_det[0][6], 'NoneType'))

		return render_template("commodities.html", biz_det = biz_det, com_dets = com_dets)
	
	elif request.method == "POST":
		com_name = request.form.get("com_name")
		com_qty = request.form.get("com_qty")

		com_pri = request.form.get("com_pri")
		com_des = request.form.get("com_des")

		print(com_pri, com_des, com_name, com_qty)

		if not com_name or not com_qty:
			return render_template("commodities.html", error_message="Name and quantity must be provided!", biz_det = biz_det,)

		else:
			current_biz = session["user_id"]
			db2.execute(
				"INSERT INTO commodities (biz_id, com_name, com_qty, com_pri, com_des) VALUES (?, ?, ?, ?, ?)",
				(current_biz, com_name, com_qty, com_pri, com_des))
			db1.commit()

			return redirect("/commodities")


@app.route("/consumables", methods=["GET", "POST"])
@login_required
def consumables():
	db1 = sqlite3.connect("shopman.db")
	db2 = db1.cursor()
	current_user = session["user_id"]

	biz_det = db2.execute("SELECT * FROM business WHERE id =?", str(current_user))
	biz_det = biz_det.fetchall()

	if request.method == "GET":
		
		con_dets = db2.execute("SELECT * FROM consumables WHERE biz_id =?", str(current_user))
		con_dets = con_dets.fetchall()

		#print(isinstance(per_det[0][6], 'NoneType'))

		return render_template("consumables.html", biz_det = biz_det, con_dets = con_dets)

	elif request.method == "POST":
		con_name = request.form.get("con_name")
		con_qty = request.form.get("con_qty")

		con_pri = request.form.get("con_pri")
		con_des = request.form.get("con_des")

		print(con_pri, con_des, con_name, con_qty)

		if not con_name or not con_qty:
			return render_template("commodities.html", error_message="Name and quantity must be provided!", biz_det = biz_det,)

		else:
			current_biz = session["user_id"]
			db2.execute(
				"INSERT INTO consumables (biz_id, con_name, con_qty, con_pri, con_des) VALUES (?, ?, ?, ?, ?)",
				(current_biz, con_name, con_qty, con_pri, con_des))
			db1.commit()

		return redirect("/consumables")


@app.route("/home")
def home():
	return render_template("home.html")


@app.route("/")
def index():
	db1 = sqlite3.connect("shopman.db")
	db2 = db1.cursor()

	if not session:
		return redirect("/home")
	else:
		current_user = session["user_id"]
		biz_det = db2.execute("SELECT * FROM business WHERE id =?", str(current_user))
		biz_det = biz_det.fetchall()
		return render_template("index.html", biz_det = biz_det)


@app.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "GET":
		return render_template("login.html")

	elif request.method == "POST":
		session.clear()

		# Ensure email was submitted
		email = request.form.get("email")

		if not email:
			return render_template("login.html", error_message="No Email given!")

		# Ensure password was submitted
		elif not request.form.get("password"):
			return render_template("login.html", error_message="Password not Provided!")

		# Query database for username
		db1 = sqlite3.connect("shopman.db")
		db2 = db1.cursor()

		rows = db2.execute("SELECT * FROM business WHERE email = ? ", (str(email),))

		rows = rows.fetchall()
		# Ensure username exists and password is correct
		if len(rows) != 1 or not check_password_hash(rows[0][4], request.form.get("password")):
			return render_template("login.html", error_message="Invalid username and/or password")

		# Remember which user has logged in
		session["user_id"] = rows[0][0]

		# Redirect user to home page
		return redirect("/")


@login_required
@app.route("/logout")
def logout():
	session.clear()
	return redirect("/home")


@login_required
@app.route("/personnel", methods=["GET", "POST"])
def personnel():
	db1 = sqlite3.connect("shopman.db")
	db2 = db1.cursor()
	if request.method == "GET":
		
		current_user = session["user_id"]
		biz_det = db2.execute("SELECT * FROM business WHERE id =?", str(current_user))
		biz_det = biz_det.fetchall()

		per_dets = db2.execute("SELECT * FROM personnel WHERE biz_id =?", str(current_user))
		per_dets = per_dets.fetchall()

		#print(isinstance(per_det[0][6], 'NoneType'))

		return render_template("personnel.html", biz_det = biz_det, per_dets = per_dets)

	elif request.method == "POST":
		per_name = request.form.get("per_name")
		per_name = per_name.title()

		per_tit = request.form.get("per_tit")
		per_tit = per_tit.title()

		per_num = request.form.get("per_num")
		per_adr = request.form.get("per_adr")

		if not per_name:
			return render_template("personnel.html", error_message="Name of Personnnel must be provided!")

		else:
			current_biz = session["user_id"]
			db2.execute(
				"INSERT INTO personnel (biz_id, per_name, per_tit, per_num, per_adr) VALUES (?, ?, ?, ?, ?)",
				(current_biz, per_name, per_tit, per_num, per_adr))
			db1.commit()

			return redirect("/personnel")


@app.route("/register", methods=["GET", "POST"])
def register():
	if request.method == "GET":
		return render_template("register.html")

	elif request.method == "POST":
		email = request.form.get("email")
		email = email.lower()

		bizname = request.form.get("bizname")
		bizname = bizname.title()

		phone = request.form.get("phone")

		password = request.form.get("password")
		confirm = request.form.get("confirm")

		hash = generate_password_hash(password)

		if not email:
			return render_template("register.html", error_message="Email not Provided!")

		elif not bizname:
			return render_template("register.html", error_message="Business name not Provided")

		elif not password or not confirm:
			return render_template("register.html", error_message="Password or Confirmation not Provided!")

		elif password != confirm:
			return render_template("register.html", error_message="Passwords don't match!")

		else:
			db1 = sqlite3.connect("shopman.db")
			db2 = db1.cursor()

			db_emails1 = db2.execute("SELECT * FROM business WHERE email = ? ", (str(email),))

			db_emails2 = db_emails1.fetchall()
			print(db_emails2)

			if len(db_emails2) > 0:
				print(email)
				return render_template("register.html", error_message="Your Email has been used already!")

			else:
				db2.execute(
					"INSERT INTO business (bizname, email, phone, hash) VALUES (?, ?, ?, ?)",
					(bizname, email, phone, hash))
				db1.commit()

				return redirect("/")

			return render_template("register.html")


@app.route("/tools", methods=["GET", "POST"])
@login_required
def tools():
	db1 = sqlite3.connect("shopman.db")
	db2 = db1.cursor()
	current_user = session["user_id"]

	biz_det = db2.execute("SELECT * FROM business WHERE id =?", str(current_user))
	biz_det = biz_det.fetchall()

	if request.method == "GET":
		
		tls_dets = db2.execute("SELECT * FROM tools WHERE biz_id =?", str(current_user))
		tls_dets = tls_dets.fetchall()

		#print(isinstance(per_det[0][6], 'NoneType'))

		return render_template("tools.html", biz_det = biz_det, tls_dets = tls_dets)
	
	elif request.method == "POST":
		tls_name = request.form.get("tls_name")
		tls_qty = request.form.get("tls_qty")

		tls_pri = request.form.get("tls_pri")
		tls_des = request.form.get("tls_des")

		print(tls_pri, tls_des, tls_name, tls_qty)

		if not tls_name or not tls_qty:
			return render_template("tools.html", error_message="Name and units must be provided!", biz_det = biz_det,)

		else:
			current_biz = session["user_id"]
			db2.execute(
				"INSERT INTO tools (biz_id, tls_name, tls_qty, tls_pri, tls_des) VALUES (?, ?, ?, ?, ?)",
				(current_biz, tls_name, tls_qty, tls_pri, tls_des))
			db1.commit()

			return redirect("/tools")

	
@app.route("/view_all", methods=["GET"])
@login_required
def view_all():
	db1 = sqlite3.connect("shopman.db")
	db2 = db1.cursor()
	current_user = session["user_id"]

	biz_det = db2.execute("SELECT * FROM business WHERE id =?", str(current_user))
	biz_det = biz_det.fetchall()

	com_dets = db2.execute("SELECT * FROM commodities WHERE biz_id =?", str(current_user))
	com_dets = com_dets.fetchall()

	con_dets = db2.execute("SELECT * FROM consumables WHERE biz_id =?", str(current_user))
	con_dets = con_dets.fetchall()

	per_dets = db2.execute("SELECT * FROM personnel WHERE biz_id =?", str(current_user))
	per_dets = per_dets.fetchall()
	
	tls_dets = db2.execute("SELECT * FROM tools WHERE biz_id =?", str(current_user))
	tls_dets = tls_dets.fetchall()

	return render_template("view_all.html", biz_det = biz_det, com_dets = com_dets, con_dets = con_dets, per_dets = per_dets, tls_dets = tls_dets)
