# Strongswan on FreeBSD for VPN infrastructure specifically for IOS Devices

This howto describes on howto install and configure Strongswan on a FreeBSD host used by Apple devices like MacOS and iOS.

For the sake of the configurations we will assume the following:

**HOSTNAME     : `vpn.example.org`**

**IPv4 ADDRESS : `192.0.2.1`**

**USERNAME     : `bob`**

**PASSWORD     : `b0b`**

**PUBLIC DNS   : `1.1.1.1,9.9.9.9`**

**VPN IP POOL  : `10.101.0.0/16`**

We will also assume that proper DNS A records for the domain has been configured otherwise the certificate generation will fail.

## Install packages
The following packages need to be installed using the command
```
pkg install -y strongswan acme.sh e2fsprogs-libuuid ldns
```

## Configure some startup services
Configure some rc vars for startup
```
sysrc hostname="vpn.example.org"
sysrc gateway_enable="YES"
sysrc strongswan_enable="YES"
sysrc strongswan_interface="stroke"
sysrc firewall_type="OPEN"
sysrc firewall_enable="YES"
sysrc firewall_nat_enable="YES"
sysrc firewall_nat_interface="192.0.2.1"
sysrc firewall_nat_flags="same_ports unreg_only reset"
```

Restart some services
```
service hostname restart
service routing restart
service ipfw start
```

## Generate and Install the certificates
Generate the certificates using [acme.sh](https://acme.sh).
```
acme.sh --issue --standalone -d vpn.example.org --keylength ec-384 --server letsencrypt 
```
Install the certificate
```
acme.sh --install-cert --ecc --ca-file /usr/local/etc/ipsec.d/cacerts/ca.pem --key-file /usr/local/etc/ipsec.d/private/vpn.example.org.pem --fullchain-file /usr/local/etc/ipsec.d/certs/vpn.example.org.cert.pem --reloadcmd 'service strongswan restart' -d vpn.example.org
```

## Configure Strongswan
There are couple of files that need to be configured for Strongswan. Let's configure one by one.

Edit the file `/usr/local/etc/ipsec.conf` with the following contents:
```
config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes

  ike=aes256gcm16-prfsha384-ecp384!
  esp=aes256gcm16-ecp384!

  dpdaction=clear
  dpddelay=900s
  rekey=no
  left=%any
  leftid=@vpn.example.org
  leftcert=vpn.example.org.cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=1.1.1.1,9.9.9.9
  rightsourceip=10.101.0.0/16
  rightsendcert=never
```

Now we need to add the users and their passwords in the format:
```
<USERNAME> : EAP <PASSWORD>
```
It's safe to not use quote characters in the passwords.

Let's edit the file `/usr/local/etc/ipsec.secret` and add one user `bob` with password `b0b`
```
: ECDSA vpn.example.org.pem
bob : EAP b0b
```

## Generate configuration profiles
It's easier to configure Apple devices with VPN Configuration Profiles. Let's generate the profiles using the following script named `gen-config.sh`
```
#!/bin/sh

VPNHOST=$(hostname -f)
cat << EOF > vpn-ios.mobileconfig
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>OnDemandEnabled</key>
        <integer>1</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>${VPNHOST}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN configuration (${VPNHOST})</string>
  <key>PayloadIdentifier</key>
  <string>com.mackerron.vpn.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

cat << EOF > vpn-mac.applescript
set vpnuser to text returned of (display dialog "Please enter your VPN username" default answer "")
set vpnpass to text returned of (display dialog "Please enter your VPN password" default answer "" with hidden answer)
set plist to "<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>AuthName</key>
        <string>" & vpnuser & "</string>
        <key>AuthPassword</key>
        <string>" & vpnpass & "</string>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>20</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>OnDemandEnabled</key>
        <integer>1</integer>
        <key>OnDemandRules</key>
        <array>
          <dict>
            <key>Action</key>
            <string>Connect</string>
          </dict>
        </array>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
      </dict>
      <key>UserDefinedName</key>
      <string>${VPNHOST}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN configuration (${VPNHOST})</string>
  <key>PayloadIdentifier</key>
  <string>com.mackerron.vpn.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>"
set tmpdir to do shell script "mktemp -d"
set tmpfile to tmpdir & "/vpn.mobileconfig"
do shell script "touch " & tmpfile
write plist to tmpfile
do shell script "open /System/Library/PreferencePanes/Profiles.prefPane " & tmpfile
delay 5
do shell script "rm " & tmpfile
EOF
```

Use the script to generate the configuration profiles for MacOS and iOS:
```
chmod +x gen-config.sh
./gen-config.sh
```
This will create two different files. `vpn-ios.mobileconfig` should be used for iOS or ipadOS while `vpn-mac.applescript` should be used for MacOS. These profiles are safe to host on a web server or send through email so that these can be downloaded on the relevant devices; in addition to that they do not contain any sensitive information. While importing in the relevant devices we will be prompted to enter our username and password. For the case of this example the username is `bob` while the password is `b0b`.

For the sake of simplicity currently the configuration shows an open firewall but a more fine grained firewal rules can be rewritten.

