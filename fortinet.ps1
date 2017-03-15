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

#==========================================#
# LogRhythm Threat Research                #
# Fortinet - SmartResponse                 #
# matt . willems @ logrhythm . com         #
# v0.1  --  April, 2016                    #
#==========================================#

# Copyright 2016 LogRhythm Inc.   
# Licensed under the MIT License. See LICENSE file in the project root for full license information.

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

# SIG # Begin signature block
# MIIdxgYJKoZIhvcNAQcCoIIdtzCCHbMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUx9/wJMUMd06Xy5fDe2G/a+9a
# OC6gghi2MIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTTMIIDu6ADAgECAhAY2tGeJn3ou0ohWM3MaztKMA0GCSqGSIb3DQEBBQUAMIHK
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsT
# FlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlT
# aWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZl
# cmlTaWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkgLSBHNTAeFw0wNjExMDgwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl
# cmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA2IFZlcmlTaWdu
# LCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlT
# aWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
# dHkgLSBHNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8kCAgpejWe
# YAyq50s7Ttx8vDxFHLsr4P4pAvlXCKNkhRUn9fGtyDGJXSLoKqqmQrOP+LlVt7G3
# S7P+j34HV+zvQ9tmYhVhz2ANpNje+ODDYgg9VBPrScpZVIUm5SuPG5/r9aGRwjNJ
# 2ENjalJL0o/ocFFN0Ylpe8dw9rPcEnTbe11LVtOWvxV3obD0oiXyrxySZxjl9AYE
# 75C55ADk3Tq1Gf8CuvQ87uCL6zeL7PTXrPL28D2v3XWRMxkdHEDLdCQZIZPZFP6s
# KlLHj9UESeSNY0eIPGmDy/5HvSt+T8WVrg6d1NFDwGdz4xQIfuU/n3O4MwrPXT80
# h5aK7lPoJRUCAwEAAaOBsjCBrzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
# AwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglpbWFnZS9naWYwITAfMAcG
# BSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNodHRwOi8vbG9nby52ZXJp
# c2lnbi5jb20vdnNsb2dvLmdpZjAdBgNVHQ4EFgQUf9Nlp8Ld7LvwMAnzQzn6Aq8z
# MTMwDQYJKoZIhvcNAQEFBQADggEBAJMkSjBfYs/YGpgvPercmS29d/aleSI47MSn
# oHgSrWIORXBkxeeXZi2YCX5fr9bMKGXyAaoIGkfe+fl8kloIaSAN2T5tbjwNbtjm
# BpFAGLn4we3f20Gq4JYgyc1kFTiByZTuooQpCxNvjtsM3SUC26SLGUTSQXoFaUpY
# T2DKfoJqCwKqJRc5tdt/54RlKpWKvYbeXoEWgy0QzN79qIIqbSgfDQvE5ecaJhnh
# 9BFvELWV/OdCBTLbzp1RXii2noXTW++lfUVAco63DmsOBvszNUhxuJ0ni8RlXw2G
# dpxEevaVXPZdMggzpFS2GD9oXPJCSoU4VINf0egs8qwR1qjtY2owggU0MIIEHKAD
# AgECAhBvzqThCU6soC46iUEXOXVFMA0GCSqGSIb3DQEBBQUAMIG0MQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWdu
# IFRydXN0IE5ldHdvcmsxOzA5BgNVBAsTMlRlcm1zIG9mIHVzZSBhdCBodHRwczov
# L3d3dy52ZXJpc2lnbi5jb20vcnBhIChjKTEwMS4wLAYDVQQDEyVWZXJpU2lnbiBD
# bGFzcyAzIENvZGUgU2lnbmluZyAyMDEwIENBMB4XDTE1MDQwOTAwMDAwMFoXDTE3
# MDQwMTIzNTk1OVowZjELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRAw
# DgYDVQQHEwdCb3VsZGVyMRgwFgYDVQQKFA9Mb2dSaHl0aG0sIEluYy4xGDAWBgNV
# BAMUD0xvZ1JoeXRobSwgSW5jLjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
# ggEBAKwJYFWf7THEfBgk4pfEUtyGbYUnZmXxJVTTtyy5f0929hCAwuy09oEHpZqD
# uregBi0oZmGo+GJT7vF6W0PZCieXFzxyNfWqJxFb1mghKo+6aweDXWXEdpp/y38k
# /+iu9MiiOFVuJzKNxMD8F6iJ14kG64K+P9gNxIu2t4ajKRDKhN5V8dSDYqdjHlM6
# Vt2WcpqUR3E2LQXrls/aYmKe1Dg9Lf8R/0OeJPLQdnXuSIhBTTdrADmhwgh9F/Q5
# Wj0hS2rURWEIdn3HQsW5xJcHuYxh3YQUIIoDybY7ZolGrRNa1gKEEZVy3iMKoK28
# HEFkuBVGtVSqRed9um99XUU1udkCAwEAAaOCAY0wggGJMAkGA1UdEwQCMAAwDgYD
# VR0PAQH/BAQDAgeAMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly9zZi5zeW1jYi5j
# b20vc2YuY3JsMGYGA1UdIARfMF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMwJQYIKwYBBQUHAgIwGQwXaHR0cHM6
# Ly9kLnN5bWNiLmNvbS9ycGEwEwYDVR0lBAwwCgYIKwYBBQUHAwMwVwYIKwYBBQUH
# AQEESzBJMB8GCCsGAQUFBzABhhNodHRwOi8vc2Yuc3ltY2QuY29tMCYGCCsGAQUF
# BzAChhpodHRwOi8vc2Yuc3ltY2IuY29tL3NmLmNydDAfBgNVHSMEGDAWgBTPmanq
# eyb0S8mOj9fwBSbv49KnnTAdBgNVHQ4EFgQUoxV4rZFrQYUJv5kT9HiDLKNevs0w
# EQYJYIZIAYb4QgEBBAQDAgQQMBYGCisGAQQBgjcCARsECDAGAQEAAQH/MA0GCSqG
# SIb3DQEBBQUAA4IBAQDtr3hDFtDn6aOruSnJYX+0YqoWREkevcGwpM0bpuJvpCRo
# Fkl8PDobpukMNQdod3/4Iee+8ZRDObYAdKygL4LbLWlaG++wxPQJUXKurRgx/xrm
# SueNFE4oXPGkGG1m3Ffvp38MfUY3VR22z5riQmc4KF2WOTl2eJFiAKTRv31Wf46X
# V3TnMeSuJU+HGNQx1+XXYuK7vgZdyxRVftjbNSW26v/6PAv7slYyiOCvYvnSVCo4
# Kdc+zHj02Nm0IfGyuO+d+992+hEEnWk/WxLwjYXMs6hcHAmuFcfMNY0/mstdWq5/
# dlT/rOBNvFOpMshhwxT1Gl5FlpLzmdj/AbGaUPDSMIIGCjCCBPKgAwIBAgIQUgDl
# qiVW/BqG7ZbJ1EszxzANBgkqhkiG9w0BAQUFADCByjELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBO
# ZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAtIEZvciBh
# dXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFzcyAzIFB1
# YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUwHhcNMTAw
# MjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtDELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3
# b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNp
# Z24uY29tL3JwYSAoYykxMDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2Rl
# IFNpZ25pbmcgMjAxMCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# APUjS16l14q7MunUV/fv5Mcmfq0ZmP6onX2U9jZrENd1gTB/BGh/yyt1Hs0dCIzf
# aZSnN6Oce4DgmeHuN01fzjsU7obU0PUnNbwlCzinjGOdF6MIpauw+81qYoJM1SHa
# G9nx44Q7iipPhVuQAU/Jp3YQfycDfL6ufn3B3fkFvBtInGnnwKQ8PEEAPt+W5cXk
# lHHWVQHHACZKQDy1oSapDKdtgI6QJXvPvz8c6y+W+uWHd8a1VrJ6O1QwUxvfYjT/
# HtH0WpMoheVMF05+W/2kk5l/383vpHXv7xX2R+f4GXLYLjQaprSnTH69u08MPVfx
# MNamNo7WgHbXGS6lzX40LYkCAwEAAaOCAf4wggH6MBIGA1UdEwEB/wQIMAYBAf8C
# AQAwcAYDVR0gBGkwZzBlBgtghkgBhvhFAQcXAzBWMCgGCCsGAQUFBwIBFhxodHRw
# czovL3d3dy52ZXJpc2lnbi5jb20vY3BzMCoGCCsGAQUFBwICMB4aHGh0dHBzOi8v
# d3d3LnZlcmlzaWduLmNvbS9ycGEwDgYDVR0PAQH/BAQDAgEGMG0GCCsGAQUFBwEM
# BGEwX6FdoFswWTBXMFUWCWltYWdlL2dpZjAhMB8wBwYFKw4DAhoEFI/l0xqGrI2O
# a8PPgGrUSBgsexkuMCUWI2h0dHA6Ly9sb2dvLnZlcmlzaWduLmNvbS92c2xvZ28u
# Z2lmMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3Bj
# YTMtZzUuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AudmVyaXNpZ24uY29tMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAzAo
# BgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItODAdBgNVHQ4E
# FgQUz5mp6nsm9EvJjo/X8AUm7+PSp50wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz
# Qzn6Aq8zMTMwDQYJKoZIhvcNAQEFBQADggEBAFYi5jSkxGHLSLkBrVaoZA/ZjJHE
# u8wM5a16oCJ/30c4Si1s0X9xGnzscKmx8E/kDwxT+hVe/nSYSSSFgSYckRRHsExj
# jLuhNNTGRegNhSZzA9CpjGRt3HGS5kUFYBVZUTn8WBRr/tSk7XlrCAxBcuc3IgYJ
# viPpP0SaHulhncyxkFz8PdKNrEI9ZTbUtD1AKI+bEM8jJsxLIMuQH12MTDTKPNjl
# N9ZvpSC9NOsm2a4N58Wa96G0IZEzb4boWLslfHQOWP51G2M/zjF8m48blp7FU3aE
# W5ytkfqs7ZO6XcghU8KCU2OvEg1QhxEbPVRSloosnD2SGgiaBS7Hk6VIkdMxggR6
# MIIEdgIBATCByTCBtDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJ
# bmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJU
# ZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykx
# MDEuMCwGA1UEAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2RlIFNpZ25pbmcgMjAxMCBD
# QQIQb86k4QlOrKAuOolBFzl1RTAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUxt74yDz620aY+eYe
# UWtPDJWnC1AwDQYJKoZIhvcNAQEBBQAEggEAajhxOj66dnYGb4IVS/la7fimplL8
# UDB7dJlvoGwdZJfT1qPRA57vvhjcZXWBgzGSHm2gf6JTjeqzNQ3x32LtXHT0NpLy
# MGbdYQJdbhXv5Jlc3o+X8ZAoKsmS4lwEq+ZL/mEFTgtz4VAXbYhm0DrrWU5ZDZBG
# SPaHpmRg8iW81v6SjcTiRvdsDdq2aBCGhOyZ1CJwcQkSX0UEipjwI2okplDaM0o8
# 085WMExWr/OcPhRycHR9L0C5CRgz898j0xpljR226qPWQf4Ks8kE/uikOrGS4TV+
# NdijhM6NqT9ls6zdCdNqIKUlZDY2mDdHG+Io7aYyg3My8e9I/l0dFhEA4qGCAgsw
# ggIHBgkqhkiG9w0BCQYxggH4MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYD
# VQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGlt
# ZSBTdGFtcGluZyBTZXJ2aWNlcyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkG
# BSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0xNzAzMTQyMTI1NTFaMCMGCSqGSIb3DQEJBDEWBBQcr4/+fQISlYmxw7hT
# dIw6ZBoi8TANBgkqhkiG9w0BAQEFAASCAQBURU/i/+xgtKH8gPfcB2H4vW+u3RHC
# xX+bXi6rmqxdybUvYhwUgNLdL8JzR5bGKRQ8qxSFSeEvSvy2nYKqYqBX8TPz5ixh
# S7JQTxrsT3ejl9Bj0UU5NAV4ytKaDdxgJjr22gClyzhoW1fLRfJu0ioZWmkijXLf
# 6WwmYHw5Jx/5S59d3g1m7ND9oBuVn8uj0LVd7hq38BHz86BW1YuNOctRWbKNBoqv
# O4WfubUutoS5GTQOzK6Ss6nmhqWttKLMEyk4eiOZF0aSekXhcT7BGRT5P1VoYrvL
# HlMwVkyXBZz5nXYMuwJ6l9IZrnC0V8/nX7kXUi9ztByGO7WVOvlK+aIc
# SIG # End signature block
