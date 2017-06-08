#!/usr/bin/python3
from wsgiref.simple_server import make_server
import urllib.parse
import traceback
import base64
import subprocess
import datetime
import uuid
import xml.etree.ElementTree
import getopt, sys
import configparser

# http://localhost:8080/share/madon.net/page/console/cloud-console/saml-settings
# http://madona.example.foo:8080/share/madon.net
# http://localhost:8080/share/madon.net
# SAML: Security Assertion Markup Language
# Assertion Consumer Service (ACS)

# samples:
# https://www.samltool.com/generic_sso_res.php
# http://simplesamlphp.googlecode.com/svn-history/r12/trunk/lib/SimpleSAML/XML/SAML20/AuthnResponse.php
# see function generate()
# idp-initiated:
# http://help.boomi.com/atomsphere/GUID-DF19946D-060E-4299-AFCF-ED3201FC2B19.html
# logout:
# http://xacmlinfo.org/2013/06/28/how-saml2-single-logout-works/
# see also sp xml:    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://madona.example.foo:8080/share/madon.net/saml/logoutrequest" ResponseLocation="http://madona.example.foo:8080/share/madon.net/saml/logoutresponse"/>
# we need 2 urls because of fig 3 page 33 of saml-profiles-2.0-os.pdf



# ###### config begin ############
# get response URLs from alfrescoSamlSpMetadata.xml

def logout_response_url():
    # return b'http://madona.example.foo:8080/share/madon.net/saml/logoutresponse'
    # return b'http://madona.example.foo:8080/share/page/saml-logoutresponse'
    return conf['logout_response_url']

def authentication_response_url():
    # return b'http://madona.example.foo:8080/share/madon.net/saml/authnresponse'
    # return b'http://madona.example.foo:8080/share/page/saml-authnresponse'
    return  conf['authentication_response_url']


def issuer1():
    # return b'my.alfresco.com-madon.net'
    return  conf['issuer1']
def issuer2():
    # return b'madon.net'
    return conf['issuer2']

def audience():
    # return b'https://my.alfresco.com-madon.net'
    # return b'http://madona.example.foo:8080'
    return conf['audience']

# ############# end of config #############



def debug(*message):
    print(*message)

def get_x509():
    f = open(conf['cert_public'],'r')
    lines=f.readlines()
    # print(lines)
    # for line in lines:
    #     print('xxx',line)
    stripped=lines[1:-1]
    stripped_data=''.join(stripped)
    stripped_data=stripped_data.strip()
    f.close()
    return stripped_data  
    
def signature_template(assertionid):
    return b'''<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <Reference URI="#'''+assertionid+b'''">
      <Transforms>
        <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </Transforms>
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue />
    </Reference>
    </SignedInfo>
  <SignatureValue />
    <KeyInfo>
      <X509Data><X509Certificate>'''+get_x509().encode('utf8')+b'''</X509Certificate></X509Data>
    </KeyInfo>

</Signature> 
'''

def command_to_sign(id_urn):
    # cert_private='/home/madon/saml/pki/server.key'
    # cert_private_password='mypass'
    command=['xmlsec1','--sign','--privkey-pem',conf['cert_private'].decode('utf8'),'--pwd',conf['cert_private_password'].decode('utf8'),'--id-attr:ID',id_urn,'--output','/tmp/response_signed.xml','/tmp/response.xml']
    
    return command

def sign(response,id_urn):
    # id_urn ='urn:oasis:names:tc:SAML:2.0:assertion:Assertion'
    # or
    # id_urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse
    f=open('/tmp/response.xml','wb')
    XX='sign'
    f.write(response)
    f.close()
    # xmlsec1 --sign --privkey-pem /home/madon/saml/pysaml2-master/example/server.key --output sample2_signed.xml /tmp/response.xml
    # /home/madon/saml/pysaml2-master/example/server.key
    #

    command=command_to_sign(id_urn)
    # command=['xmlsec1','--sign','--privkey-pem','/home/madon/saml/pki/server.key','--output','/tmp/response_signed.xml','/tmp/response.xml']
    debug(XX,'command=',' '.join(command))
    proc = subprocess.Popen(command)
    outs, errs = proc.communicate()
    debug(XX,outs, errs)
    f=open('/tmp/response_signed.xml','rb')
    response=f.read()
    f.close()
    return response


def generate_id():
    return str(uuid.uuid4()).encode('utf8')



def forge_response_logoutresponse(inresponseto):
    responseid=generate_id()
    issueinstant=datetime.datetime.now(datetime.timezone.utc).isoformat().encode('utf8')

    response=b'''<samlp:LogoutResponse 
   ID="'''+responseid+b'''" 
   Version="2.0" 
   IssueInstant="'''+issueinstant+b'''" 
   Destination="'''+logout_response_url()+b'''" 
   InResponseTo="'''+inresponseto+b'''"
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" >
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">'''+issuer1()+b'''</Issuer>
  '''+signature_template(responseid)+b'''
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
</samlp:LogoutResponse>'''
    return response

# xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 

def forge_response_authnresponse(inresponseto):

    assertionid=generate_id() # b'_f41c8f91-294b-42c6-bfc5-c43d5b6461d0'
    responseid=generate_id() # b'_3b68164b-4be0-4ba1-863c-d892877b1164'
    sessionindex=generate_id()
    

    issueinstant=datetime.datetime.now(datetime.timezone.utc).isoformat().encode('utf8') # e.g b'2015-03-12T13:19:01.886Z'
    assertionexpire=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)).isoformat().encode('utf8')
    notbefore=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=30)).isoformat().encode('utf8')


    response=b'''<samlp:Response 
   ID="'''+responseid+b'''" 
   Version="2.0" 
   IssueInstant="'''+issueinstant+b'''" 
   Destination="'''+authentication_response_url()+b'''" 
   Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" 
   InResponseTo="'''+inresponseto+b'''" 
   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">'''+issuer1()+b'''</Issuer>
<samlp:Status>
   <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
</samlp:Status>
<Assertion 
   ID="'''+assertionid+b'''" 
   IssueInstant="'''+issueinstant+b'''" 
   Version="2.0" 
   xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
   <Issuer>'''+issuer2()+b'''</Issuer>
   '''+signature_template(assertionid)+b'''
   <Subject>
     <NameID>'''+conf['email']+b'''</NameID>
     <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <SubjectConfirmationData 
          InResponseTo="'''+inresponseto+b'''" 
          NotOnOrAfter="2015-03-12T13:24:01.886Z" 
          Recipient="'''+authentication_response_url()+b'''" />
     </SubjectConfirmation>
   </Subject>
  <Conditions 
        NotBefore="2015-03-12T13:19:01.870Z" 
        NotOnOrAfter="2015-03-12T14:19:01.870Z">
    <AudienceRestriction>
          <Audience>'''+audience()+b'''</Audience>
    </AudienceRestriction>
  </Conditions>
  <AttributeStatement>
     <Attribute Name="Email"><AttributeValue>'''+conf['email']+b'''</AttributeValue></Attribute>
  </AttributeStatement>
  <AuthnStatement 
       AuthnInstant="'''+issueinstant+b'''" 
       SessionIndex="'''+sessionindex+b'''">
     <AuthnContext>
            <AuthnContextClassRef>urn:federation:authentication:windows</AuthnContextClassRef>
     </AuthnContext>
   </AuthnStatement>
  </Assertion>
</samlp:Response>'''
    return response

def forge(environ):
    XX="forge"
    status = '200 OK' # HTTP Status
    headers = [('Content-type', 'text/html; charset=utf-8')] # HTTP Headers
    content=b"we only support POST"

    if environ['REQUEST_METHOD']=='POST':
        debug(XX,"environ=",environ)
        content=b'<h1>Alex IdP server</h1>we got a post'
        debug(XX,dir(environ['wsgi.file_wrapper']))
        debug(XX,'wsgi.input',environ['wsgi.input'])
        data = environ['wsgi.input'].read(int(environ['CONTENT_LENGTH']))
        debug(XX,'data',data)
        qs = urllib.parse.parse_qs(data)
        debug(XX,'qs',qs)
        debug(XX, 'qs.keys()', qs.keys())
        samlrequest=b''
        for key in qs.keys():
            debug(XX,'key',key,qs[key])
            content=content+b'<h2>'+key+b'</h2>'
            if key in [b'SAMLRequest',b'KeyInfo',b'Signature']:
                # pass
                bdecoded=base64.standard_b64decode(qs[key][0])
                debug(XX,key,'decoded',bdecoded,)
                if key in [b'SAMLRequest']:
                    samlrequest=bdecoded
                content=content+b'\n\n<pre>'+bdecoded.replace(b'<',b'\n&lt;')+b'</pre>'
            else:
                content=content+b'\n\n<pre>'+qs[key][0].replace(b'<',b'\n&lt;')+b'</pre>'

        # we should make checks (signature) on samlrequest

        # extract AssertionConsumerServiceURL (acs) and ID from XML request
        root = xml.etree.ElementTree.fromstring(samlrequest)
        debug(XX,'root.tag',root.tag)
        debug(XX,'root.attrib',root.attrib)

        content=content+b'<hr><hr><h2>SAMLRequest root</h2>'
        content=content+b'Tag: '+root.tag.encode('utf8')
        content=content+b'<br>Attrib: '+', '.join(root.attrib).encode('utf8')

        if root.tag=="{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest":
            # alfrescoSamlSpMetadata.xml 
            # http://localhost:8080/share/madon.net/proxy/alfresco/saml/sp/metadata?a=true
            # <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            # Location="http://madona.example.foo:8080/share/madon.net/saml/logoutrequest"
            # ResponseLocation="http://madona.example.foo:8080/share/madon.net/saml/logoutresponse"/>
            # <md:AssertionConsumerService isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://madona.example.foo:8080/share/madon.net/saml/authnresponse" index="0"/> 
            acs=logout_response_url() # b'http://madona.example.foo:8080/share/madon.net/saml/logoutresponse'
            human_action=b'Logout'
            forge_response_fct=forge_response_logoutresponse
            id_urn='urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse'
    # urn ='urn:oasis:names:tc:SAML:2.0:assertion:Assertion'
    # or
    # urn:oasis:names:tc:SAML:2.0:protocol:LogoutResponse
        else:
            acs=root.attrib['AssertionConsumerServiceURL'].encode('utf8')
            human_action=b'Authenticate'
            forge_response_fct=forge_response_authnresponse
            id_urn='urn:oasis:names:tc:SAML:2.0:assertion:Assertion'
        inresponseto=root.attrib['ID'].encode('utf8')
        content=content+b'<hr><h2>Request contained:</h2>'
        content=content+b'acs (AssertionConsumerServiceURL)='+acs+b'<br>'
        content=content+b'inresponseto (ID)='+inresponseto+b'<br>'


        
        response=forge_response_fct(inresponseto)
        response=sign(response,id_urn)


        
        content=content+b'<hr><h2>we will send SAMLResponse</h2><pre>'
        content=content+response.replace(b'<',b'&lt;')
        content=content+b'</pre><hr><h1>'+human_action+b'</h1>'
        content=content+b'<form action="'+acs+b'" method="POST">'
        content=content+b'<input type="hidden" name="SAMLResponse" value="'+base64.standard_b64encode(response)+b'"/>'
        content=content+b'<input type="submit"></form>'
        # payload=""
        # for chunk in environ['wsgi.file_wrapper']:
        #      debug(XX,chunk)
    return (status,headers,content)


def check_xmlsec1():
    # raise an error if xmlsec1 is not installed
    try:
        subprocess.run(["xmlsec1"],stdout=subprocess.DEVNULL)
    except:
        raise
    
def hello_world_app(environ, start_response):
    XX="hello_world_app"
    # debug(XX,"environ=",environ)
    # debug(XX,environ[],environ[])
    (status,headers,content)=forge(environ)
    start_response(status, headers)
    return [content,]

def display_conf(intro):
    print("+++++",intro,"+++++")
    for key in conf.keys():
        print("default",key,'=',conf[key])

    
if __name__ == "__main__":
    conf={}

    # default config
    conf['cert_private']=b'/home/madon/saml/pki/server.key'
    conf['cert_public']=b'/home/madon/saml/pki/server.crt'
    conf['cert_private_password']=b'mypass'
    conf['email']=b'idpuser@madon.net'
    conf['showhelp']=False
    
    conf['logout_response_url']=b'http://madona.example.foo:8080/share/page/saml-logoutresponse'
    conf['authentication_response_url']=b'http://madona.example.foo:8080/share/page/saml-authnresponse'
    conf['audience']=b'http://madona.example.foo:8080'
    conf['issuer1']=b'my.alfresco.com-madon.net'
    conf['issuer2']=b'madon.net'

    conf['config_file']='config.ini'


    
    display_conf("Default parameter values")
        

    optlist, list = getopt.getopt(sys.argv[1:], 'e:hp:P:w:c:')
    
    # check if there is a config file in command line
    for option in optlist:
        if option[0] == '-c':
            conf['config_file']=option[1]


    print("Checking values to overwrite from",conf['config_file'],"..................")
        
# parse the config file
    config = configparser.ConfigParser()
    config.read(conf['config_file'])
    sections=config.sections()

    config_array=config.defaults()

    for akey in config_array:
        print("reading",akey,"from",conf['config_file'],"and setting to",config_array[akey])
        conf[akey]=config_array[akey].encode('utf8')

    display_conf("New parameter values after parsing config file")


# second pass to override config file
    for option in optlist:
        if option[0] == '-e':
            conf['email']=option[1].encode('utf8')
        if option[0] == '-h':
            conf['showhelp']=True
        if option[0] == '-p':
            conf['cert_private']=option[1].encode('utf8')
        if option[0] == '-P':
            conf['cert_public']=option[1].encode('utf8')
        if option[0] == '-w':
            conf['cert_private_password']=option[1]
            
    display_conf("New and final parameter values after parsing command line")
    

    
    if conf['showhelp']:
        print("""Alex Minimal IdP        
Usage: ./saml_wsgi.py [ options ... ]
       where options include:

-h        : this Help message
-e <email>: the Email address of the user the IdP knows about. 
            ---- Default: """+conf['email'].decode('utf8')+"""
-p <private_cert> : the private key used to sign SAML messages. 
            ---- Default: """+conf['cert_private']+"""
-P <public_cert> : the Public cert used to embed in SAML messages. That cert needs also to be uploaded to the SL (Alfresco)
            ---- Default: """+conf['cert_public']+"""
-w <password>  : the passWord for the private key
            --- Default: """+conf['cert_private_password']+"""
-c <config_file> : default config.ini

About the server:
================
This is a minimal IdP written in python.
It knowns only one user at a time.
Digital Signature is delagated to an external program: xmlsec1 (to be installed).
On Debian, to install: apt-get install  xmlsec1
To digitally sign, you will need a pair (public key, private key)

A *minimal* server:
==================
The server is *minimal*, in the sense that it is close to the minimum number of lines to write to get a successful login with alfresco and a successful logout. It knows about only one user at a time. It does not know about more than one SP (when doing a SLO it does not log out from other SP as Alfresco is the only SP it knows about)
There is no password or identity management.
There is no automatic parsing of SP Metadata XML file. The field that Alfrescp SP expects is hardcoded.
There is no validation of the signature when reading message sent by the SP (we hower do sign our messages sent to the SP as Alfresco refuses to take them into account if not signed, for security reasons).

The goal is to make testing of Alfresco SAML (as a SAMLv2 Service Provider) the simplest possible. 

Alfresco SP configuration:
==========================
In the (Cloud) SAML configuiration page, the three URL parameters:
IdP AuthenticationRequest Service URL
IdP SingleLogoutRequest Service URL
IdP SingleLogoutResponse Service URL

should be set to this server URL (http://<ip>:<port>)

The cert to upload is the same as the value of the -P option.

""")
        quit()
    print("Starting minimal IdP server....")
    print("Signing command will be:")
    print(' '.join(command_to_sign('<id_urn>')))
    print('IdP knowing user:',conf['email'])
    check_xmlsec1()
    print("X509 data used will be (from public key):")
    print(get_x509())
    # quit()
    httpd = make_server('', 8000, hello_world_app)
    print("Serving on port 8000...")
    # Serve until process is killed
    httpd.serve_forever()


    # errors: date in future, replayed ID, no base64, no ID, no encryption, no email, etc...
