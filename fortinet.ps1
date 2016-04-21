#Requires -Version 4.0
# FortiGate-Add-IP-To-Group
# Guy Harper
# 2016-02-03
# 
# This script may be used to query and modify the policy objects of a 
# FortiGate firewall via its API
# 
# The following steps are performed:
#
# 1. Authenticate to the API and gather session cookie and CSRF token
# 2. GET group membership for 'logrhythm-blocklist' group
# 4. Add specified object to 'logrhythm-blocklist' group

# Heavily rewritten by Matt Willems
# 2016-02-08

# Copyright 2016 LogRhythm Inc.   
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at;
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.

# Assign args
param (
    [string]$username = $(throw "Usage: fortinet.ps1 <username> <password> <fortinet ip> <port> <command> <target>"),
    [string]$pass = $(throw "Usage: fortinet.ps1 <username> <password> <fortinet ip> <port> <command> <target>"),
    [string]$fortiIP = $(throw "Usage: fortinet.ps1 <username> <password> <fortinet ip> <port> <command> <target>"),
    [string]$port = $(throw "Usage: fortinet.ps1 <username> <password> <fortinet ip> <port> <command> <target>"),
    [string]$command = $(throw "Usage: fortinet.ps1 <username> <password> <fortinet ip> <port> <command> <target>"),
    [string]$object = $(throw "Usage: fortinet.ps1 <username> <password> <fortinet ip> <port> <command> <target>")
)

# Set up a trap to properly exit on terminating exceptions
trap [Exception] 
{
	write-error $("TRAPPED: " + $_)
	exit 1
}

# debug: echo params
Write-Host "Username: $username"
#Write-Host "Passowrd: $pass"
Write-Host "TargetIP: $fortiIP"
Write-Host "DestPort: $port"
Write-Host "Command:: $command"
Write-Host "Object::: $object"
Write-Host ""

# Ignore invalid SSL certification warning
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

#data validation
if ($command -eq "get"){
    Write-Host "Get $object"
}
elseif ($command -eq "add_ip"){
    if ($object -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"){
    Write-Host "Valid IP."
    }
    else {
    Write-Host "Invalid IP."
    exit 1
    }
}
elseif ($command -eq "add_domain"){
    if ($object -match "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"){
    Write-Host "Valid IP. Use add_ip instead."
    exit 1
    }
    elseif ($object -match "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"){
    Write-Host "Valid Domain name."
    }
    else {
    Write-Host "Invalid Domain name."
    exit 1
    }
}
else {
    Write-Host "Invalid command. Please use add_ip or add_domain."
    exit 1
}


# Get session token & CSRF token

# Create URL with the correct calling parameters
$authURL = "https://${fortiIP}:${port}/logincheck"
$baseURL = "https://${fortiIP}:${port}"

# Echo the URL back to the SmartResponse Status viewer
#Write-Host "AuthURL:: $authURL"

# define POST parameters
#$authParams = @{username=$username;secretkey=$pass}
$authParams = "username=${username}&secretkey=${pass}"
#Write-Host "POSTdata: $authParams"

#ignore self signed certs
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

#find current working directory and make a path to curl.exe
$path = Get-Location
$curl = "$path\curl.exe"

#make auth URL
$newURL = "${authURL}?${authParams}"
#Write-Host "NewURL::: $newURL"

#execute curl POST to auth url with creds (see above)
$output = & $curl -s -X POST --header "Content-Type: application/x-www-form-urlencoded" --insecure -D - "$newURL"
#Write-Host "Output::: $output"

#test for HTTP response 200. If so, parse cookie and token from response
if($output -match "200 OK"){
$cookie = ($output -split ';')[3]
$cookie = $cookie.TrimStart("Set-Cookie: ")
Write-Host "Cookie::: $cookie"
$token = ($output -split ';')[6]
$token = $token.TrimStart('Set-Cookie: "ccsrftoken="')
$token = $token.TrimEnd('"')
Write-Host "Token:::: $token"
}
else{ #if no 200 response, auth failed
Write-Host "Authentication Failure."
exit
}
if($cookie -match "APSCOOKIE_\d+=`"0%260`""){ #if returned 200 but cookie is 00, auth failed
Write-Host "Authentication Failure."
exit
}

#function to add IP to fortigate
function Add-FortinetIP {
param($baseURL, $cookie, $token, $command, $object)

#set up vars. URL to correct API resource, generate a GUID and create a name, build JSON object containing target IP
$createURL = "${baseURL}/api/v2/cmdb/firewall/address"
$GUID = [guid]::NewGuid()
$name = "LogRhythm-$GUID"

if ($command -eq "add_ip"){
    $data = "{ \`"vdom\`" : \`"root\`", \`"json\`" : { \`"name\`" : \`"$name\`", \`"subnet\`" : \`"$object/32\`" } }"
    Write-Host "Creating Address Object for IP: $object..."
    Write-Host "URL: $createURL"
    Write-Host "Address Name: $name"
    #Write-Host "Data: $data"

    #curl POST to create address object from above json data
    $createoutput = & $curl -s -X POST -H "Cookie: $cookie" -H "X-CSRFTOKEN: $token" -H "Content-Type: application/json" -d "${data}" --insecure "$createURL"
    #Write-Host "Create output: $createoutput"
    }
elseif ($command -eq "add_domain"){
    $data = "{ \`"vdom\`" : \`"root\`", \`"json\`" : { \`"name\`" : \`"$name\`", \`"type\`" : \`"wildcard-fqdn\`", \`"fqdn\`" : \`"*.$object\`" } }"
    Write-Host "Creating Address Object for domain: $object..."
    Write-Host "URL: $createURL"
    Write-Host "Address Name: $name"
    #Write-Host "Data: $data"

    #curl POST to create address object from above json data
    $createoutput = & $curl -s -X POST -H "Cookie: $cookie" -H "X-CSRFTOKEN: $token" -H "Content-Type: application/json" -d "${data}" --insecure "$createURL"
    Write-Host "Create output: $createoutput"
    }
return $name
}

if ($command.Equals("add_ip") -Or $command.Equals("add_domain")){
#call function to create address object, return name
$name = Add-FortinetIP $baseURL $cookie $token $command $object
Write-Host "Function created $name"

#this block returns the existing contents of the address group. that data must be modified to include the new address object created above and PUT back to the API
#possible future ability to pass in group name
$group = "logrhythm-blocklist"
Write-Host "Get details of $group..."
$getURL = "${baseURL}/api/v2/cmdb/firewall/addrgrp/${group}"
Write-Host "Get URL: $getURL"
#curl to GET the address group
$getoutput = & $curl -s -X GET -H "Cookie: $cookie" -H "X-CSRFTOKEN: $token" -H "Content-Type: application/json" --insecure -D - "$getURL"

#split output on newlines into an array
$newoutput = $getoutput -split "`n"

#size the array and set variables
$y = $newoutput.GetUpperBound(0)
$x = 1
$z = 0
$json

#iterate through array elements, find the beginning of the JSON, start adding elements from array to json variable
DO {
    $string = $newoutput[$x]
    if ($string -contains "{"){
        $z = 1
        }
    if ($z -eq 1){
        $json = $json + $string
        }
    $x++
} While ($x -le $y)

#display json
ConvertFrom-Json $json | select -expand results | select -expand member #| Select name

#this is where i start modifying the member data. find the correct json node
$json -match "`"member`".*?\]"
$members = $matches[0]

#remove the close bracket, add new entry inside of JSON formatting
$members = $members.TrimEnd("]")
$members = $members + ", { `"name`" : `"$name`" } ]"
Write-Host ""
#Write-Host $members

$members = $members -replace "`"","\`""
$addURL = "${baseURL}/api/v2/cmdb/firewall/addrgrp"
#$data = "{ \`"vdom\`" : \`"root\`", \`"json\`" : { \`"member\`" : [ { \`"name\`" : \`"$object\`" }, { \`"name\`" : \`"test-matt-chrome-1\`" }, { \`"name\`" : \`"LogRhythm-12e04c82-25de-45fc-8890-0d15612e1be1\`" } ] } }"
$data = "{ \`"vdom\`" : \`"root\`", \`"json\`" : { $members } }"

#Write-Host ""

#Write-Host $data



Write-Host "Adding $name to address group $group..."
#Write-Host "URL: $addURL/$group"
#Write-Host "Data: $data"

$addoutput = & $curl -s -X PUT -H "Cookie: $cookie" -H "X-CSRFTOKEN: $token" -H "Content-Type: application/json" -d "$data" --insecure "$addURL/$group"
Write-Host "Add output: $addoutput"
    if($addoutput -match "`"http_status`":200"){
    Write-Host "200: Added $name to $group."
    }
    else{
    Write-Host "HTTP Error. Failed to add $name to $group."
    exit
    }
}

if ($command.Equals("get")){
Write-Host "Get details of $object..."
$getURL = "${baseURL}/api/v2/cmdb/firewall/addrgrp/${object}"
Write-Host "Get URL: $getURL"
$getoutput = & $curl -s -X GET -H "Cookie: $cookie" -H "X-CSRFTOKEN: $token" -H "Content-Type: application/json" --insecure -D - "$getURL"

#$getoutput

$newoutput = $getoutput -split "`n"

$y = $newoutput.GetUpperBound(0)
$x = 1
$z = 0
$json

DO {
    $string = $newoutput[$x]
    if ($string -contains "{"){
        $z = 1
        }
    if ($z -eq 1){
        $json = $json + $string
        }
    $x++
} While ($x -le $y)

#$members = $json.
ConvertFrom-Json $json | select -expand results | select -expand member | Select name
}
#Log out of API
$logout = & $curl -s -X POST "$baseURL/logout"
