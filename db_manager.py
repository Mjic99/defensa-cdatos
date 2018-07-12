import sqlite3

con = sqlite3.connect("direcciones.db")
c = con.cursor()

def inicializar():
	try:
		c.execute("select * from direcciones")
		c.fetchall()
	except sqlite3.OperationalError as e:
		c.execute("CREATE TABLE direcciones(ip text, mac text)")
		con.commit()

def guardar_dir(data):
	c.execute("INSERT INTO direcciones VALUES (?, ?)",(str(data["ip"]), str(data["mac"])))
	con.commit()
	a=c.execute("select * from direcciones")

def buscar_dir(mac):
	c.execute("SELECT * FROM direcciones WHERE mac=?",(mac,))
	if c.fetchone() is None:
		return False
	else: return True

def limpiar():
	c.execute("DELETE FROM direcciones")
	con.commit()

def mostrar():
	c.execute("SELECT * FROM direcciones")
	print(c.fetchall())

def on_exit():
	con.close()