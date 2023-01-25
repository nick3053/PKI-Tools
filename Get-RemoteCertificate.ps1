<#
.Synopsis
   With this function you can retrieve certificate information from any given website/host for multiple protocols

.EXAMPLE
   Get-RemoteCertificate -url https://swisscom.com

.INPUTS
   always input the URL with the protocol (e.g. https://swisscom.com)

.OUTPUTS
   This function displays Subject, Issuer, Validity and SANs of any received certificate

.NOTES
   Name: Get-RemoteCertificate.ps1
   Author: Nick Brülhart
   Created: 25.01.2023
   To check bad certs I have used https://badssl.com/

#>
function Get-RemoteCertificate {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory=$true)][string]$url,
        [parameter(Mandatory=$false)]$port = 443 #i have added this since you maybe want to check against LDAPs, WinRM etc.
    )
    #Set all variables to $null, just in case my ISE wants to hang on to the values between runs....
    $req = $null
    $Cert = $null
    $SAN = $null

    #Let's disable SSL-Checks since we may encounter self-signed or expired certificates
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    #Make use of the .NET web request
    Write-Host "Trying to reach $url on port $port"
    try{
        $req = [Net.HttpWebRequest]::Create($url)
    } catch {
        Write-Error $_ #If there is an error, this should display it
        break
    }

    #Check and see if $req is still empty
    if(!$req){
        Throw "Unable to connect to $url on port $port"
        break
    } 
    else #if not, lets move on
    {
        Write-Host "Established connection to $url on port $port" 
        try{
            $req.GetResponse() | Out-Null #To retrieve information we need to use the .GetResponse() method first but we don't want this output displayed 
        } catch {
            Write-Host "Exception while checking URL $url"
            break
        }

        #To get SANs wen need the certificate handle extension object and filter for OID 2.5.29.17, (oidref.com/2.5.29.17)
        #so let's create an instance of the X509Certificate class with the data received
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$req.ServicePoint.Certificate.Handle

        #we will also safe the full certificate to check the validity
        $Certificate = [Security.Cryptography.X509Certificates.X509Certificate2]$req.ServicePoint.Certificate
        
        try{
            $CertValid = Test-Certificate $Certificate -ErrorAction SilentlyContinue

        } catch {
            $CertValid = $false
        }
        

        try {
            #if there are SANs in the certificate, they should now be saved in the $SAN variable
            $SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "
        } catch {
            #or maybe there aren't any (which should not be the case with public TLS-certificates!)
            $SAN = "no additional SANs"
        }
        #We want the output as PSCustomObjects since this makes further handling easier
        $output = [PSCustomObject]@{
            'Subject' = $req.ServicePoint.Certificate.Subject
            'Issuer' = $req.ServicePoint.Certificate.GetIssuerName()
            'Start Date' = $req.ServicePoint.Certificate.GetEffectiveDateString()
            'End Date' = $req.ServicePoint.Certificate.GetExpirationDateString()
            'SANs' = $SAN | Out-String #Converts input object into string
            'Valid?' =  $CertValid #This checks the validity against the client

             }
        $output  #this just outputs our variable, but you could easely reuse this further since we created a PSCustomObject

             
        }
        #Revert Change to ignore SSL warnings before closing function
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null
   
}
