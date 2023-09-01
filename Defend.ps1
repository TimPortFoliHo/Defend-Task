param (
    [string]$argument = ""
)

function testDNSBlock {
    # Assigning ethernet 3
    $interfaceAlias = "Ethernet 3"

    # Getting DNS server address for Ethernet 3
    $dnsServers = (Get-DnsClientServerAddress -InterfaceAlias $interfaceAlias).ServerAddresses

    # Checking if DNS server addresses were retrieved
    if ($dnsServers) {
        $dnsServersString = ($dnsServers -join ', ')
        Write-Output "DNS Servers for $interfaceAlias : $dnsServersString"

        # Determine the IP address of malware.testcategory.com
        $malwareIpAddress = [System.Net.Dns]::GetHostAddresses("malware.testcategory.com")[0].ToString()

        # Displaying the IP address of malware.testcategory.com
        Write-Output "IP address of malware.testcategory.com: $malwareIpAddress"

        # Outputting that host isnt using DNS filtering
        if ($malwareIpAddress -ne "0.0.0.0") {
            Write-Output "The host malware.testcategory.com is not using DNS filtering."
        }
    } else {
        # Display a message if DNS server information was not found
        Write-Output "DNS server information not found for $interfaceAlias."
    }
}

# Function to enable DNS over HTTPS (DoH)
function enableDoH {
    # Set registry value to enable DoH
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
    Set-ItemProperty -Path $regPath -Name "EnableAutoDoH" -Value 2

    # Display message about enabling DoH
    Write-Output "DNS over HTTPS (DoH) will be enabled."

    # Prompt user to reboot or schedule a reboot
    $rebootPrompt = Read-Host "A reboot is required to enable DoH. Reboot now? (Y/N)"
    if ($rebootPrompt -eq "Y" -or $rebootPrompt -eq "y") {
        Write-Output "Rebooting..."
        Restart-Computer -Force
    } else {
        Write-Output "Please reboot your computer to apply the changes."
    }
}

# Function to set up Quad9 DNS over HTTPS (DoH)
function setupQuadDoH {
    # Changing DNS server of Ethernet 3 to 1.1.1.2
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 3" -ServerAddresses "1.1.1.2"

    # Register the DoH template
    Add-DnsClientDohServerAddress -ServerAddress "1.1.1.2" -Template "https://security.cloudflare-dns.com/dns-query" -AutoUpgrade $True

    # Set up DoH using the registry
    $guid = (Get-NetAdapter -InterfaceAlias "Ethernet 3").InterfaceGuid

    # Creating registry path
    $registryPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\Doh\1.1.1.2"
    New-Item -Path $registryPath -Force

    # Enable DoH by setting DohFlags property to 1
    Set-ItemProperty -Path $registryPath -Name "DohFlags" -Value 1

    Write-Output "Quad9 DNS over HTTPS (DoH) has been set up."
}

# Function to reset DNS settings back to default
function resetDoH {
    # Reset DNS server of Ethernet 3 to the original value (10.0.2.3)
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet 3" -ServerAddresses "10.0.2.3"

    # Remove DoH configuration on Ethernet 3
    Remove-DnsClientDohServerAddress -ServerAddress "1.1.1.2"

    # Remove DoH registry settings
    $guid = (Get-NetAdapter -InterfaceAlias "Ethernet 3").InterfaceGuid
    $registryPath = "HKLM:\System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\$guid\DohInterfaceSettings\Doh\1.1.1.2"
    Remove-Item -Path $registryPath -Force

    # Get the updated DNS server addresses for Ethernet 3 after reset
    $updatedDnsServers = (Get-DnsClientServerAddress -InterfaceAlias "Ethernet 3").ServerAddresses
    Write-Output "DNS settings and DoH configuration have been reset."
    Write-Output "Updated DNS servers for Ethernet 3 after reset: $($updatedDnsServers -join ', ')"

}

function CreateBlockRule {
    $ruleName = "BlockOutboundHTTP"
    $existingRule = Get-NetFirewallRule | Where-Object {$_.DisplayName -eq $ruleName}

    if ($null -ne $existingRule) {
        Write-Output "Deleting existing rule: $($existingRule.DisplayName)"
        Remove-NetFirewallRule -DisplayName $ruleName
    }

    $ruleAction = "Block"
    $ruleProtocol = "TCP"
    $rulePort = 80
    $ruleDirection = "Outbound"
    $ruleDescription = "Block outbound connections on TCP port 80"

    # This portion of code is based on the Microsoft documentation for New-NetFirewallRule
    # Documentation URL: https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2022-ps
    New-NetFirewallRule -DisplayName $ruleName -Action $ruleAction -Protocol $ruleProtocol -LocalPort $rulePort -Direction $ruleDirection -Description $ruleDescription
    Write-Output "Firewall rule created to block outbound connections to TCP port 80.
Rule:BlockOutboundHTTP enabled"
}

function TestBlocking {
    param (
        [string]$TargetComputer = "google.com"
    )
    
    $testConnectionResult = Test-NetConnection -ComputerName $TargetComputer -Port 80

    if ($testConnectionResult.TcpTestSucceeded) {
        Write-Output "TCP port 80 (HTTP) connection to $TargetComputer is successful. Traffic is not blocked."
    } else {
        Write-Output "TCP port 80 (HTTP) connection to $TargetComputer is blocked."
    }
}

function DisableBlockRule {
    $existingRule = Get-NetFirewallRule | Where-Object {$_.DisplayName -eq $ruleName}
    if ($null -ne $existingRule) {
        Write-Output "Disabling firewall rule: $($existingRule.DisplayName)"
        Set-NetFirewallRule -DisplayName $ruleName -Enabled False
        Write-Output "Firewall rule disabled."
    } else {
        Write-Output "Firewall rule '$ruleName' not found."
    }
}

# Check the command-line argument are valid
if ($argument -eq "test-DoH") {
    Write-Output "Calling testDNSBlock function..."
    testDNSBlock
}
elseif ($argument -eq "enable-DoH") {
    Write-Output "Calling enableDoH function..."
    enableDoH
}
elseif ($argument -eq "setupQuad-DoH") {
    Write-Output "Calling setupQuadDoH function..."
    setupQuadDoH
}
elseif ($argument -eq "reset-DoH") {
    Write-Output "Calling resetDoH function..."
    resetDoH
}
elseif ($argument -eq "create-block") {
    Write-Output "Creating block rule..."
    CreateBlockRule
}
elseif ($argument -eq "test-blocking") {
    Write-Output "Testing blocking..."
    TestBlocking
}
elseif ($argument -eq "disable-block") {
    Write-Output "Disabling block rule..."
    DisableBlockRule
}
else {
    # Display error message and to select from option
    Write-Output "Error: Unknown argument.
Please select one of the following valid arugment:
'test-DoH', 'enable-DoH', 'setupQuad-DoH', 'reset-DoH',
'create-block', 'test-blocking', 'disable-block'"
}
