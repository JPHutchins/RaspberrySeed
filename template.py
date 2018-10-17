from flask import render_template
from flask import Flask, redirect, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
from urllib.request import urlopen
import json
import requests
import subprocess
import os
import sys
from copy import deepcopy
from shutil import copyfile
import time

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = set(['zip', 'ovpn', 'conf', 'pem', 'text', 'txt', 'crt'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'my unobvious secret key'

OVPNobtained = 'FALSE'

#need to add a .conf file to save state of program and refresh global variables appropriately
unzipped = []
otherFiles = []
VPNservers = []
populated = ''
PublicIP = ''
realISP = ''
City = ''
Region = ''
Country = ''
selectServer = False
inputAuth = False
pasteCert = False
inputAuthSaved = False
pasteCertSaved = False
VPNserversSaved = False
copyInTheCert = False
VPNservers = []

masterConfigDict = {"ovpn": [], "cert": [], "auth": [], "pastedCert": '', "script": []}
masterConfigDict.clear()
masterConfigDict = {"ovpn": [], "cert": [], "auth": [], "pastedCert": '', "script": []}
makeConf = []
readyToWrite = []
makeConf.clear()
readyToWrite.clear()
moveScript = False
crtPath = False
pemPath = False
authPath = False
movePemFrom = ''
movePemTo = ''
moveCrtFrom = ''
moveCrtTo = ''
vpnChosenB = False
vpnActive = False


def allowed_file(filename):
	return '.' in filename and \
        	filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
			
			
@app.route('/', methods = ['GET', 'POST'])
def home():
	resetDicts()
	firstBoot = False
	global vpnChosenB
	global vpnActive
	global PublicIP
	global realISP
	global City
	global Region
	global Country

	data = str(urlopen('http://checkip.dyndns.com/').read())
	StartMark = '<body>Current IP Address: '
	EndMark = '</body>'	
	IPstart = data.find(StartMark) + len(StartMark)
	IPend = data.find(EndMark)
	PublicIP = ''
	for i in range(IPstart, IPend):
		PublicIP = PublicIP + data[i]


	ipinfoR = requests.get('http://ipinfo.io')
	ipinfo = json.loads(ipinfoR.text)
	City = ipinfo["city"]
	PublicIP = ipinfo["ip"]	
	Region = ipinfo["region"]
	Country = ipinfo["country"]

	if vpnActive == False:
		ispData = str(urlopen('https://www.whoismyisp.org/ip/' + PublicIP).read())
		StartMark = '<p class="isp">'
		EndMark = '</p>'
		ispStart = ispData.find(StartMark) + len(StartMark)
		ispEnd = ispData.find(EndMark)
		realISP = ''
		for i in range(ispStart, ispEnd):
			realISP = realISP + ispData[i]
		#print(realISP)
		if firstBoot == True:
			log = open("./config/config.json", "w")
			log.write("{\"realISP\":\"" + realISP +"\"}\n{\"realIP\":\"" + PublicIP +"\"}\n")
			log.close()

		


	return render_template('home.html', vpnChosenB=vpnChosenB, PublicIP=PublicIP, realISP=realISP, City=City, Region=Region, Country=Country)

@app.route('/hello/')
@app.route('/hello/<name>')
def hello(name=None):

	data = str(urlopen('http://checkip.dyndns.com/').read())
	StartMark = '<body>Current IP Address: '
	EndMark = '</body>'	
	IPstart = data.find(StartMark) + len(StartMark)
	IPend = data.find(EndMark)
	PublicIP = ''
	for i in range(IPstart, IPend):
		PublicIP = PublicIP + data[i]

	ipinfoR = requests.get('http://ipinfo.io')
	ipinfo = json.loads(ipinfoR.text)
	City = ipinfo["city"]
	PublicIP = ipinfo["ip"]	
	Region = ipinfo["region"]
	Country = ipinfo["country"]

	return render_template('hello.html', name=name, PublicIP=PublicIP, City=City, Region=Region, Country=Country)

@app.route('/VPNproviders/<vpnChosen>/')
def servers(vpnChosen=None):
	
	VPNservers = []
	VPNserverNames = []
	uploaded = False
	if vpnChosen == "mullvad":
		isMullvad = True
	else:
		isMullvad = False
	with open('./vpnProviders/VPNproviders.json') as f:
		data = json.loads(f.read())
		name = data[vpnChosen]["name"]
		configMethod = data[vpnChosen]["config"]
		statusURL = data[vpnChosen]["statusURL"]
		wgetURL = data[vpnChosen]["wgetURL"]
		infoURL = data[vpnChosen]["url"]
		confTrue = data[vpnChosen]["conf"]
		authPreConfig = data[vpnChosen]["authPreConfig"]
		certificateEmbed = data[vpnChosen]["certificateEmbed"]
		serverNameFormat = data[vpnChosen]["serverNameFormat"]
		speedTest = data[vpnChosen]["speedTest"]
		if speedTest == "True":
			speedTest = True
		else:
			speedTest = False
		speedURL = data[vpnChosen]["speedURL"]	
		speedInfoURL = data[vpnChosen]["speedInfoURL"]
	
	print(speedTest)

	if (configMethod == "auto"):
		autoConfig = True
		ovpnPath = "./ovpnfiles/" + vpnChosen
		if os.path.isdir(ovpnPath):
			unzipped = sorted(os.listdir(ovpnPath + "/ovpn"))
			for index, VPNserver in enumerate(unzipped): #make the list of servers look nice...except for IPVanish
				VPNservers.append(unzipped[index])
				fullName = VPNserver
				trueName = ""
				start = fullName.find(serverNameFormat[0]) + len(serverNameFormat[0])
				end = fullName.find(serverNameFormat[1])
				#print(start, end)
				for i in range(start, end):
					trueName = trueName + fullName[i]
				VPNserverNames.append(trueName)
				
				#if isVPN[1] == '.ovpn':
				#	VPNservers.append(unzipped[index])
				#	VPNserverNames.append(isVPN[0])
				#elif isVPN[1] == '.conf':
			#		VPNservers.append(unzipped[index])
			#		VPNserverNames.append(isVPN[0])
			#	else:
			#		otherFiles.append(unzipped[index])

		if len(VPNservers) > 0:
			populated = str(len(VPNservers)) + ' OVPN configuration files are already downloaded.'
		else:
			populated = 'No OVPN configuration files are loaded yet.'
		return render_template('servers.html', speedInfoURL=speedInfoURL, vpnChosen=vpnChosen, infoURL=infoURL, speedTest=speedTest, speedURL=speedURL, autoConfig=autoConfig, VPNservers=VPNserverNames, populated=populated, name=name, PublicIP=PublicIP, realISP=realISP, City=City, Region=Region, Country=Country)
	
	elif configMethod == "manual":
		ovpnFound = False
		autoConfig = False
		certFound = False
		authFound = False
		ovpnFound = False
		gotFiles = False
		certMissing = True
		authMissing = True
		ovpnMissing = True
		ovpnFounds = ''
		authFounds = ''
		certFounds = ''
		fileName = ''
		showUserFiles = ''
		fileCountDict = {}
		fileNames = os.listdir('./uploads/')
			
		if fileNames:
			uploaded = True
			fileNameDict= {}
			for fileName in fileNames:
				ext = os.path.splitext('./uploads/' + fileName)[1]
				fileNameDict[ext] = fileName
			if '.zip' in fileNameDict:
				showUserFiles = showUserFiles + "\nInflated " + fileNameDict[".zip"] + "..."
				subprocess.call(['unzip', '-o', './uploads/' + fileNameDict[".zip"], '-d', './uploads/'])
				subprocess.call(['rm', './uploads/' + fileNameDict[".zip"]])
			
			fileList = []				
			fileList = findFiles('./uploads', fileList)
			
			fileNameDict= {'.pem':[], '.crt':[], '.txt':[], '.text':[], '.ovpn':[], '.conf':[]}
			for fileName in fileList:
				ext = os.path.splitext('./uploads/' + fileName[1])[1]
				if ext in fileNameDict:
					fileNameDict[ext].append(fileName)
				else:
					fileNameDict.setdefault(ext, []).append(fileName)
				showUserFiles = showUserFiles + "\n" + fileName	[1]	

			lookingFor = {"cert": ['.pem', '.crt'], "auth": ['.txt', '.text'], "ovpn": ['.ovpn', '.conf'], "script": ['']}
			sendThemHere = {}
			sortedDict = sortAndCountFileTypes(lookingFor, fileNameDict, sendThemHere)[0]
			if 'script' not in [*sortedDict]:
				sortedDict.setdefault('script', [])

			fileCountDict['certCount'] = (len(sortedDict['cert']))
			if fileCountDict['certCount'] > 0:
				certMissing = False
				for item in sortedDict["cert"]:
					certFounds = certFounds + "\n" + item[0]

			fileCountDict['authCount'] = (len(sortedDict['auth']))
			if fileCountDict['authCount'] > 0:
				authMissing = False
				for item in sortedDict["auth"]:
					authFounds = authFounds + "\n" + item[0]
			
			fileCountDict['ovpnCount'] = (len(sortedDict['ovpn']))
			if fileCountDict['ovpnCount'] > 0:
				ovpnMissing = False
				ovpnFound = True
				for item in sortedDict["ovpn"]:
					ovpnFounds = ovpnFounds + "\n" + item[0]

			if certFound and authFound and ovpnFound:
				gotFiles = True
			else:
				gotFiles = False
			
			global masterConfigDict

			masterConfigDict['ovpn'] = sortedDict['ovpn']
			masterConfigDict['cert'] = sortedDict['cert']
			masterConfigDict['script'] = sortedDict['script']

			global inputAuthSaved

			if len(sortedDict['auth']) == 1:

				with open((sortedDict['auth'][0][1]), 'r') as f: #idiot check for auth.text formatting and read into memory
					authText = f.readlines()
					i = 0
					masterConfigDict['auth'] = [None, None]
					for line in authText:
						if len(line) > 1 and i < 2:
							masterConfigDict['auth'][i] = line
							i += 1
			elif inputAuthSaved == False:
				masterConfigDict['auth'] = []		
			#print(masterConfigDict)		


		

		return render_template('servers.html', ovpnFound = ovpnFound, fileCountDict=fileCountDict, isMullvad=isMullvad, speedInfoURL=speedInfoURL, certMissing=certMissing, authMissing=authMissing, ovpnMissing=ovpnMissing, gotFiles=gotFiles, certFounds=certFounds, authFounds=authFounds, ovpnFounds=ovpnFounds, showUserFiles=showUserFiles, uploaded=uploaded, fileName=fileName, vpnChosen=vpnChosen, infoURL=infoURL, speedTest=speedTest, speedURL=speedURL, autoConfig=autoConfig, name=name, PublicIP=PublicIP, realISP=realISP, City=City, Region=Region, Country=Country)

	

@app.route('/OVPNzip/', methods = ['POST'])
def ConfigureVPN(): #this is a function to refresh the ovpn files... needs sorting into the correct folders though!

	configURL = 'https://www.privateinternetaccess.com/openvpn/openvpn-ip.zip'
	subprocess.call(['wget', '-O', 'THISDAZIP.zip', configURL])
	subprocess.call(['unzip', '-o', 'THISDAZIP.zip', '-d', './piaOVPN'])
	OVPNobtained = 'TRUE'
	return redirect('/servers/', code=302)

def StartVPN():
	
	subprocess.call("OpenVPNargs") 

@app.route('/goConfigure/<vpnChosen>/', methods = ['POST', 'GET'])
def configserver(vpnChosen=None):
	
	vpnChosen = vpnChosen
	global masterConfigDict
	global selectServer
	global inputAuth
	global pasteCert
	global VPNservers
	global inputAuthSaved
	global pasteCertSaved
	global VPNserversSaved

	with open('./vpnProviders/VPNproviders.json') as f:
		data = json.loads(f.read())
		name = data[vpnChosen]["name"]
		configMethod = data[vpnChosen]["config"]
		statusURL = data[vpnChosen]["statusURL"]
		wgetURL = data[vpnChosen]["wgetURL"]
		infoURL = data[vpnChosen]["url"]
		confTrue = data[vpnChosen]["conf"]
		authPreConfig = data[vpnChosen]["authPreConfig"]
		certificateEmbed = data[vpnChosen]["certificateEmbed"]
		serverNameFormat = data[vpnChosen]["serverNameFormat"]
		speedTest = data[vpnChosen]["speedTest"]
		if speedTest == "True":
			speedTest = True
		else:
			speedTest = False
		speedURL = data[vpnChosen]["speedURL"]	
		speedInfoURL = data[vpnChosen]["speedInfoURL"]	

	if configMethod == "auto":
		if 'selectedServer' in request.form:
			masterConfigDict['ovpn'] = [((request.form['selectedServer'] + ".ovpn"), ("./ovpnfiles/" + vpnChosen + "/ovpn/" + request.form['selectedServer'] + ".ovpn"))]
		certs = os.listdir("./ovpnfiles/" + vpnChosen + "/cert/")
		print(certs)
		for cert in certs:
			print(cert)
			masterConfigDict['cert'].append((cert, "./ovpnfiles/" + vpnChosen + "/cert/" + cert))
		currentURL="goConfigure.html"
		if 'username' in request.form: 
			masterConfigDict['auth'] = [(request.form['username'], request.form['password'])]
	
	if "selectedServerManual" in request.form:
		selectedServerManual = request.form['selectedServerManual']
		tempList = deepcopy(masterConfigDict['ovpn'])
		for index, entry in enumerate(tempList):
			if entry[0] == selectedServerManual:
				masterConfigDict['ovpn'] = []
				masterConfigDict['ovpn'].append(tempList[index])
				break
		selectServer = False	
		VPNserversSaved = True
	if len(masterConfigDict['ovpn']) > 1 and configMethod == "manual":
		selectServer = True
		
		VPNservers = deepcopy(masterConfigDict['ovpn'])
		for i, VPNserver in enumerate(VPNservers):
			VPNservers[i] = VPNserver[0]
		VPNservers.sort()
	
	if "username" in request.form:
		masterConfigDict['auth'] = [request.form['username'], request.form['password']]
		inputAuth = False
		inputAuthSaved = True
	if len(masterConfigDict['auth']) == 0 or len(masterConfigDict['auth']) > 2:
		inputAuth = True
	
	copyInTheCert = False
	pasteCertNotValid = False
	if "certificate" in request.form:
		masterConfigDict['pastedCert'] = request.form.get('certificate')
		pasteCert = False
		pasteCertSaved = True
	if len(masterConfigDict['cert']) == 0:
		pasteCert = True
	
	if len(masterConfigDict['pastedCert']) > 25:
		pasteCert = False
		pasteCertNotValid = False
		copyInTheCert = True
	if len(masterConfigDict['cert']) == 0 and len(masterConfigDict['pastedCert']) <= 25:
		pasteCertNotValid = True


	global makeConf
	
	global readyToWrite

	if len(masterConfigDict['ovpn']) == 1 and len(masterConfigDict['auth']) == 2 and ((len(masterConfigDict['cert']) >= 1) or (len(masterConfigDict['pastedCert']) > 25 )):
		print("Going to make config...")
		global makeConf
		global pemPath
		global crtPath
		global moveScript
		global movePemFrom
		global movePemTo 
		global moveCrtFrom 
		global moveCrtTo 
	
		makeConf.clear()
		
		with open(masterConfigDict['ovpn'][0][1], 'r') as ovpnF:
			ovpnL = ovpnF.readlines()
			for i, line in enumerate(ovpnL):
			
				if line[0:14] == 'auth-user-pass':
					makeConf.insert(i, 'auth-user-pass /etc/openvpn/auth.txt\n')
					authPath = True
				elif line[0:2] == 'ca':
					for item in masterConfigDict['cert']:
						if item[1].find('.crt') >= 0:
							moveCrtFrom = item[1]
							moveCrtTo = '/etc/openvpn/' + item[0]
							makeConf.insert(i, 'ca ' + '/etc/openvpn/' + item[0] + '\n')
							crtPath = True
				elif line[0:10] == 'crl-verify':
					for item in masterConfigDict['cert']:
						if item[1].find('.pem') >= 0:
							movePemFrom = item[1]
							movePemTo = '/etc/openvpn/' + item[0]
							makeConf.insert(i, 'crl-verify ' + '/etc/openvpn/' + item[0] + '\n')
							pemPath = True
				elif line[0:2] == 'up' or line [0:4] == 'down':
					makeConf.insert(i, ovpnL[i])
					moveScript = True
				elif line[0] != '\n':
					makeConf.insert(i, ovpnL[i])
			if copyInTheCert == True:
				makeConf.append(masterConfigDict['pastedCert'])
		
		#print(makeConf)
		
		readyToWrite.clear()
		if authPath == True:
			readyToWrite.append("Write /etc/openvpn/auth.txt from authentication")
		if crtPath == True:
			readyToWrite.append("Write " + moveCrtTo + " from " + moveCrtFrom)
		if pemPath == True:
			readyToWrite.append("Write " + movePemTo + " from " + movePemFrom)
		if moveScript == True:
			if len(masterConfigDict['script']) == 1:
				readyToWrite.append("Write /etc/openvpn" + masterConfigDict['script'][0][0] + " from " + masterConfigDict['script'][0][1])
				
		confName = deepcopy(masterConfigDict['ovpn'][0][0])
		newName = os.path.splitext(confName)[0]
		readyToWrite.append("Write the OpenVPN configfuration below to /etc/openvpn/" + newName + '.conf')
		

	
		
		
		return render_template('goConfigure.html', readyToWrite=readyToWrite, makeConf=makeConf, pasteCertNotValid=pasteCertNotValid, pasteCertSaved=pasteCertSaved, inputAuthSaved=inputAuthSaved, VPNserversSaved=VPNserversSaved, pasteCert=pasteCert, inputAuth=inputAuth, selectServer=selectServer, VPNservers=VPNservers, name=name, speedInfoURL=speedInfoURL, vpnChosen=vpnChosen)
	#print(request.form.get('config')) #todo need to be able to edit conf

	return render_template('goConfigure.html', pasteCertNotValid=pasteCertNotValid, pasteCertSaved=pasteCertSaved, inputAuthSaved=inputAuthSaved, VPNserversSaved=VPNserversSaved, pasteCert=pasteCert, inputAuth=inputAuth, selectServer=selectServer, VPNservers=VPNservers, name=name, speedInfoURL=speedInfoURL, vpnChosen=vpnChosen)

@app.route('/goConfigure/conf', methods=['GET', 'POST'])
def command(cmd=None):
	global readyToWrite
	global masterConfigDict
	

	with open('/etc/openvpn/auth.txt', 'w') as f:
			for line in masterConfigDict['auth']:
				if '\n' in line:
					f.write(line)
				else:
					f.write(line + '\n')
				
			print("Wrote authentication file at /etc/openvpn/auth.txt")
			#write to json
	newName = os.path.splitext(masterConfigDict['ovpn'][0][0])[0]
	with open('/etc/openvpn/' + newName + ".conf", 'w') as f:
		f.writelines(makeConf)
		print("Wrote OpenVPN configuration to " + '/etc/openvpn/' + newName + ".conf")
		#write to json
	if crtPath == True:
		copyfile(moveCrtFrom, moveCrtTo)
		print("Wrote " + moveCrtTo + " from " + moveCrtFrom)
		#write to json
	if pemPath == True:	
		copyfile(movePemFrom, movePemTo)
		print("Wrote " + movePemTo + " from " + movePemFrom)
		#write to json
	if moveScript == True and len(masterConfigDict['script']) == 1:
		copyfile(masterConfigDict['script'][0][1], "/etc/openvpn/" + masterConfigDict['script'][0][0])
		subprocess.call(['chmod', '776', "/etc/openvpn/" + masterConfigDict['script'][0][0]])
		print("Moved script")
	print("Configuration complete.  Starting OpenVpn")

	
	global vpnChosenB
	global vpnActive
	vpnChosenB = True
	vpnActive = True
	subprocess.Popen(['sudo', '/usr/sbin/openvpn', '--config', '/etc/openvpn/' + newName + '.conf'])
	return '{"success": True}'
	

@app.route('/configMullvad/', methods = ['POST', 'GET'])
def configMullvad():


	status = ''

	return render_template('servers.html', VPNservers=VPNservers, populated=populated, status = status, filedata=inFileData)

@app.route('/uploadtest/<vpnChosen>/', methods=['GET', 'POST'])
def upload_file(vpnChosen=None):
	if request.method == 'POST':
        	# check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
        	# if user does not select file, browser also
       	 	# submit an empty part without filename
		if file.filename == '':
			flash('No selected file')
			return redirect(request.url)
		if file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			print(filename, "saved to ", UPLOAD_FOLDER)
		return redirect('/VPNproviders/' + vpnChosen, code=302)
	status = ''
	return redirect('/VPNproviders/' + vpnChosen, code=302)

@app.route('/rmUploads/<vpnChosen>/', methods=['GET', 'POST'])
def rmUploads(vpnChosen=None):
	subprocess.call(['rm', '-r', './uploads'])
	subprocess.call(['mkdir', './uploads'])
	global masterConfigDict
	global selectServer
	global inputAuth
	global pasteCert
	global inputAuthSaved
	global pasteCertSaved
	global VPNserversSaved
	selectServer = False
	inputAuth = False
	pasteCert = False
	inputAuthSaved = False
	pasteCertSaved = False
	VPNserversSaved = False
	masterConfigDict.clear()
	masterConfigDict = {"ovpn": [], "cert": [], "auth": [], "pastedCert": '', "script": []}
	makeConf.clear()

	return redirect('/VPNproviders/' + vpnChosen, code=302)

@app.route('/VPNproviders/', methods=['GET', 'POST'])
def VPNproviders():
	resetDicts()
	return render_template('whatVpnServiceDoYouHave.html', PublicIP=PublicIP, realISP=realISP, City=City, Region=Region, Country=Country)



def writeFiles(**kwargs):
	serverpath = kwargs.get('serverpath', None)
	servername = kwargs.get('servername', None)

	ovpnFile = open(serverpath, 'r')
	ovpnList = list(ovpnFile)
	
	for index, line in enumerate(ovpnList):
		if line == 'auth-user-pass\n':
			ovpnList[index] = 'auth-user-pass auth.text\n'
		if line == 'crl-verify crl.rsa.2048.pem\n':
			ovpnList[index] = 'crl-verify /etc/openvpn/crl.rsa.2048.pem\n'
		if line == 'ca ca.rsa.2048.crt\n':
			ovpnList[index] = 'ca /etc/openvpn/ca.rsa.2048.crt\n'
	print(ovpnList)

	confFile = open("/etc/openvpn/" + servername + ".conf", "w+")
	confFile.writelines(ovpnList)

	ovpnFile.close
	confFile.close

	#authFile = open('/etc/openvpn/auth.text', 'w')
	#authFile.write(username + '\n' + password + '\n')
	#authFile.close

	if os.path.isfile('/etc/openvpn/crl.rsa.2048.pem') == False:
		os.rename('./piaOVPN/crl.rsa.2048.pem', '/etc/openvpn/crl.rsa.2048.pem')
	if os.path.isfile('/etc/openvpn/ca.rsa.2048.crt') == False:
		os.rename('./piaOVPN/ca.rsa.2048.crt', '/etc/openvpn/ca.rsa.2048.crt')
	
	if os.path.isfile('/etc/openvpn/crl.rsa.2048.pem') and os.path.isfile('/etc/openvpn/ca.rsa.2048.crt') and os.path.isfile("/etc/openvpn/" + servername + ".conf") and os.path.isfile('/etc/openvpn/auth.text'):
		status = servername + ' VPN has been configured correctly'
	else:
		status = servername + ' VPN configuration failed to write files at /etc/openvpn'

	return 0

def makeConfig(**kwargs):
	pathToOvpn = kwargs.get('pathToOvpn', None) #string
	pathToAuth = kwargs.get('pathToAuth', None)	#string
	pathsToCert = kwargs.get('pathsToCert', None) #List!
	currentURL = kwargs.get('currentURL', None) #string
	authFile = kwargs.get('authFile', None) #List  0 is username and 1 is password

	if os.path.isfile(pathToOvpn):
		ovpnFile = []
		ovpnFileF = open(pathToOvpn, 'r') #ovpnFile is a list in memory
		for line in ovpnFileF:
			ovpnFile.append(line)
		
		isTherePathToAuth = os.path.isfile(pathToAuth)
		if isTherePathToAuth or authFile: 
			
			if isTherePathToAuth:   #copy credentials into memory
				with open(pathToAuth) as auth:
					credentials = auth.readlines
					for i, line in enumerate(credentials):
						authFile[i] = line

			setAuth = True
			for eachLine in ovpnFile:		#set path to the auth.txt
				if eachLine.find("auth-user-pass") >= 0:
					eachLine = "auth-user-pass /etc/openvpn/auth.txt"
					setAuth = False
			if setAuth:
				ovpnFile.append("auth-user-pass /etc/openvpn/auth.txt")
		
			
			if os.path.isfile(pathsToCert[0]):
				certNames = []
				for k, pathToCert in enumerate(pathsToCert):	#now we are converting the path names to just file names
					if k == len(pathsToCert):
						break
					for i in range(len(pathToCert) - 1, -1, -1):
						if pathToCert[i] == "/":
							break
						if i == 0:
							print(pathToCert, " is not a valid path.")	
							ovpnFileF.close()
							#return render_template(currentURL, success=False, needCert=True, needAuth=False)
					for j in range(len(pathToCert) - i, len(pathToCert)):
						certNames.append(pathsToCert.extend(pathToCert))
					print("Found ", certNames)

				gotCert = False
				for certName in certNames:	
					for eachLine in ovpnFile:	#search each line of the file for certName
						startsAt = eachLine.find(certName) >= 0
						if startsAt >= 0:
							eachLine = eachLine[:startsAt] + "etc/openvpn/" + certName  #when it finds a certificate adds absolute path
							certNames.remove(certName) #and remove it from the list - certNames contains certs not found in the file
							gotCert = True
				if gotCert:
					print("Set certificate paths in OVPN.")
					print("Completed OVPN configuration")
					configDict["ovpn"] = ovpnFile
					configDict["auth"] = authFile
					configDict["certPath"] = pathsToCert
					configDict["embedCert"] = False
					ovpnFile.close()
					return render_template(currentURL, success=True, needCert=False, needAuth=False, configDict=configDict)

			else: #look for embedded certifcate and if all else fails ask user
				noCert = True
				for eachLine in ovpnFile:
					if eachLine.find("-----BEGIN CERTIFICATE-----") >= 0:
						noCert = False
						print("Found certificate in OVPN.")
						print("Completed OVPN configuration.")
						configDict["ovpn"] = ovpnFile
						configDict["auth"] = authFile
						configDict["certPath"] = "NULL"
						configDict["embedCert"] = True
						ovpnFile.close()
						return render_template(currentURL, success=True, needCert=False, needAuth=False, configDict=configDict)
				if noCert:
					print("Could not find a certificate.")
					ovpnFileF.close()
					return render_template(currentURL, success=False, needCert=True)	

		else:											#prompt user for username and password
			needAuth = True
			print("Missing auth.txt.  Need username and password to create auth.txt.")
			ovpnFile.close()
			return render_template(currentURL, needAuth=needAuth, success=False)
			
	else:
		print("There is no *.ovpn or *.conf file at the path specified.")
		return render_template(currentURL, success=False)


def findFiles(currentPath, emptyPathList):
	"searches for files in arg1 and all subdirectories of arg1 and returns list. arg2 is the name of the empty list you want to fill with file names"
	pathList = emptyPathList
	
	currentFolder = os.listdir(currentPath)
	for item in currentFolder:
		if os.path.isdir(currentPath + "/" + item):
			newPath = currentPath + "/" + item
			findFiles(newPath, pathList)
		else:
			pathList.append((item, currentPath + "/" + item))


	return(pathList)


def sortAndCountFileTypes(descriptionsAndExts, sourceDict, destDict):
	"descriptionsAndExts:  {'description':[ext1, ext2, ext3, etc]}"
	vanillaDict = {}
	vanillaDict = deepcopy(sourceDict)

	extsInDict = [*sourceDict]
	descsInDescriptionsDict = [*descriptionsAndExts]

	for desc in descsInDescriptionsDict:
		for exts in extsInDict:
			for extsQ in descriptionsAndExts[desc]:
				if extsQ == exts:
					destDict.setdefault(desc, []).extend(sourceDict[exts])
					del sourceDict[exts]

	leftOver = [*sourceDict]
	for exts in leftOver:
		destDict.setdefault('unknown', []).extend(sourceDict[exts])
	
	return(destDict, vanillaDict)

def resetDicts():
	subprocess.call(['rm', '-r', './uploads'])
	subprocess.call(['mkdir', './uploads'])
	global masterConfigDict
	global selectServer
	global inputAuth
	global pasteCert
	global inputAuthSaved
	global pasteCertSaved
	global VPNserversSaved
	selectServer = False
	inputAuth = False
	pasteCert = False
	inputAuthSaved = False
	pasteCertSaved = False
	VPNserversSaved = False
	masterConfigDict.clear()
	masterConfigDict = {"ovpn": [], "cert": [], "auth": [], "pastedCert": '', "script": []}
	makeConf.clear()
	readyToWrite.clear()
	return 0