import os, json, os.path, base64, zlib, hashlib, shutil, requests, zipfile

outFormat = "\033[0;33;40m"
outFormatError = "\033[1;31;40m"
outFormatPre = "\033[1;34;40m"
outFormatOk = "\033[1;32;40m"
outFormatDefault = "\033[0;37;40m"
execBw = "bw"
windows = False
outFolder = "output/" #dejar "" para exportar a esta carpeta
tmpFolder = "tmp/"

def printShit(t, error = False, ok = False):
    if not error:
        if not ok:
            print(outFormatPre + "[GET-KEYS] " + outFormat + t + outFormatDefault)
        else:
            print(outFormatPre + "[GET-KEYS] " + outFormatOk + t + outFormatDefault)
    else:
        print(outFormatPre + "[GET-KEYS] " + outFormatError + t + outFormatDefault)
            

def inputShit(t, error = False):
    if not error:
        return input(outFormatPre + "[GET-KEYS] " + outFormat + t + outFormatDefault + " ")
    else:
        return input(outFormatPre + "[GET-KEYS] " + outFormatError + t + outFormatDefault + " ")

def bwCmd(cmd):
    if not windows:
        return "./" + execBw + " " + cmd
    else:
        return execBw + " " + cmd
        

printShit("Iniciando...")
if os.name == 'nt':
    execBw = "bw.exe"
    windows = True

if windows:
    printShit("Corriendo en Windows")
else:
    printShit("Corriendo en Linux")

#create tmp folder
if not os.path.exists(tmpFolder):
    os.makedirs(tmpFolder)

#check if bw client exists.

r = requests.get("https://vault.bitwarden.com/download/?app=cli&platform=windows")

if not os.path.isfile(execBw):
    printShit("No se encontro el cliente de bitwarden. Descargando...", True)
    reqUrl = "https://vault.bitwarden.com/download/?app=cli&platform="
    if windows:
        reqUrl += "windows"
    else:
        reqUrl += "linux"
    try:
        printShit("Descargando: " + reqUrl, False)
        r = requests.get(reqUrl, allow_redirects=True)
        with open("bw.zip", "wb") as bwFile:
            #data = zlib.decompress(r.content, 16+zlib.MAX_WBITS)
            bwFile.write(r.content)
            bwFile.close()
        printShit("OK.", False, True)
    except Exception as error:
        printShit("No se pudo descargar: " + repr(error) + "\n", True)
        exit()
    
    try:
        printShit("Extrayendo: " + execBw, False)
        with zipfile.ZipFile("bw.zip", 'r') as zip_ref:
            zip_ref.extractall(".")
        printShit("OK.", False, True)
        if not windows:
            printShit("Ejecutando chmod: " + execBw, False)
            os.system("sudo chmod +x " + execBw)
            printShit("OK.", False, True)
        printShit("Limpiando: " + execBw, False)
        os.remove("bw.zip")
        printShit("OK.", False, True)
    except Exception as error:
        printShit("No se pudo extraer: " + repr(error) + "\n", True)
        exit()

printShit("Iniciando sesion en bitwarden...")
ret = os.system(bwCmd("login"))
if ret:
    printShit("Si no se pudo ejecutar el comando " + execBw + ", corra el siguiente comando:", True)
    printShit("sudo chmod +x " + execBw, True)
    printShit("Ejecute de nuevo el script.", True)
    
fListName = tmpFolder + "folderList.json"
if not os.path.isfile(fListName):
    printShit("Create folder list")
    ret = os.system(bwCmd("list folders") + " > " + fListName)
    if ret:
        printShit("No se pudo seguir. Ejecute el comando export BW_SESSION=.... y corra de nuevo", True)
        exit()

#get keys folder id
keysfolderid = ""
with open(fListName, "r") as json_file:
    for i in json.load(json_file):
        if i.get("name") == "keys":
            keysfolderid = i.get("id")

keysfolderidbytes = keysfolderid.encode('ascii')
keysfolderidbase64 = base64.b64encode(keysfolderidbytes, altchars=None).decode('ascii')

keyListName = tmpFolder + keysfolderidbase64 + ".json"
if not os.path.isfile(keyListName):
    printShit("Get keys list")
    ret = os.system(bwCmd("list items --folderid ") + keysfolderid + " > " + keyListName)


#create out folder
if not os.path.exists(outFolder):
    os.makedirs(outFolder)

with open(keyListName, "r") as json_file:
    for i in json.load(json_file):
        #print(json.dumps(i, indent=4, sort_keys=True))
        printShit("Procesando: " + i.get("name"))
        outFileName = outFolder + i.get("name") + ".key"

        for j in i.get("fields"):
            if (j.get("name") == "encoding"):
                encoding = j.get("value")
                printShit(" - " + j.get("name") + ": " + j.get("value"))
            if (j.get("name") == "md5"):
                md5 = j.get("value")
                printShit(" - " + j.get("name") + ": " + j.get("value"))
        
        if (encoding == "none"):
            try:
                with open(outFileName, "w+") as write_file:
                    file_str = i.get("notes")
                    file_str = file_str[:-1] #remover ultimo newline
                    write_file.write(file_str)
                    write_file.close()
                #md5 check:
                with open(outFileName, "rb") as read_file:
                    md5_hash = hashlib.md5()
                    md5_hash.update(read_file.read())
                    digest = md5_hash.hexdigest()
                    read_file.close()
                    if not (md5 == digest):
                        raise Exception("md5 checksum fail: Expected md5: " + md5 + " - got: " + digest)
                printShit(" - OK.\n", False, True)
            except Exception as error:
                printShit(" - " + repr(error) + "\n", True)
                
        if (encoding == "base64"):
            try:
                with open(outFileName, "w+b") as write_file:
                    file_data = base64.b64decode(i.get("notes").encode('ascii'))
                    write_file.write(file_data)
                    write_file.close()
                #md5 check:
                with open(outFileName, "rb") as read_file:
                    md5_hash = hashlib.md5()
                    md5_hash.update(read_file.read())
                    digest = md5_hash.hexdigest()
                    read_file.close()
                    if not (md5 == digest):
                        raise Exception("md5 checksum fail: Expected md5: " + md5 + " - got: " + digest)
                printShit(" - OK.\n", False, True)
            except Exception as error:
                printShit(" - " + repr(error) + "\n", True)
        
        if (encoding == "gzip, base64"):
            try:
                with open(outFileName, "w+") as write_file:
                    file_str = zlib.decompress(base64.b64decode(i.get("notes").encode('ascii')), 16+zlib.MAX_WBITS).decode('ascii')
                    file_str = file_str[:-1] #remover ultimo newline
                    write_file.write(file_str)
                    write_file.close()
                #md5 check:
                with open(outFileName, "rb") as read_file:
                    md5_hash = hashlib.md5()
                    md5_hash.update(read_file.read())
                    digest = md5_hash.hexdigest()
                    read_file.close()
                    if not (md5 == digest):
                        raise Exception("md5 checksum fail: Expected md5: " + md5 + " - got: " + digest)
                printShit(" - OK.\n", False, True)
            except Exception as error:
                printShit(" - " + repr(error) + "\n", True)
        

#delete temp files
try:
    shutil.rmtree(tmpFolder)
except OSError as e:
    print("Error: %s - %s." % (e.filename, e.strerror))