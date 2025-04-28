#!/usr/bin/env python3

import base64
import os
import google.generativeai as genai
import vt
import imaplib
import re
from email import parser
from email.policy import default
import time

#How program works
print("""\nHello user, we will need to gather some insight into your malicious situation. 
      \nPlease enter your email to allow me to gather information and then forward the email suspected of malicious activity to [your configured mailing account].\n""")

#Gathering User Insight
email = input("Enter your email: ")


#Configuring email server and logging into access email
imap_server=imaplib.IMAP4_SSL('imap.gmail.com')
imap_server.login('local.lock.app@gmail.com', os.environ.get('EMAIL_PASSWORD'))

#Starts time to find email
print('Waiting for forwarded email...\n')
start_time = time.time()

#Loops until email is found
while True:
    current_time = time.time()
    imap_server.select('INBOX')
    result, data = imap_server.search(None, 'FROM "{}"'.format(email))

    #Attempts to find lastest email sent by user
    try:
        message_id = data[0].split()[-1]
        break

    except:
        #Gives two minute time limit to retrieve email
        if current_time - start_time >= 120:
            print('Time to send email exceeded. Stopping program now.')
            quit()

    time.sleep(10)


#Retrieves the full message in the raw email format.
result, data = imap_server.fetch(message_id, 'RFC822')
raw_email = data[0][1].decode('utf-8')

#Deletes email sent by user and closes server
imap_server.store(message_id, '+FLAGS', '\\Deleted')
imap_server.close()

#Converts email into Email object
msg = parser.Parser(policy=default).parsestr(raw_email)

#Parse email for attachments and suspected threat actor
forwarded_msg = msg.get_payload()[0].get_payload()
from_email = re.search(r'From: .* <([\w\.]*@\w*\.\w*)>', forwarded_msg)
links = re.findall(r'https?://[\w.]*', forwarded_msg)
links = list(set(links))


#VirusTotal Assessment
client = vt.Client(os.environ.get("VT_API_KEY"))

#Gathers the analysis stats from each url 
reviews = []
for link in links:
    #Converts url to acceptable format and gets analysis stats
    url_id = vt.url_id(link)
    url = client.get_object("/urls/{}".format(url_id))
    reviews.append(url.last_analysis_stats)

#Closes VirusTotal client
client.close()

#Configure Gemini
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.0-flash')

#Creating prompt for comprehensive analysis
user_insight = user_analysis = """
    Using the email "{}", analyze the name and domain to determine who they are (ex. personal, corporate account, etc.), 
    potentially valuable assets (ex. passwords, capital, corporate secrets or access, etc.), 
    and what vectors a possible attacker could use to reach them (ex. compromised email, email list, etc.) 
    and create a sequence of the three items. Ensure each point of analysis is under 40 words long. 
    The only output should be as follows: "persona: ", "assets: ", "attack vectors: "
    """.format(email)

# Generate content
response = model.generate_content(user_analysis)
print(response.text)

# prompt = """I am a {} who has recently recieved an email that I suspect of malicious intent. 
# I hold {}, which are potentially valuable to attackers. If the email was of malicious intent, 
# the attacker might have reached me from {}. Please analyze the email in a single concise pargraph,
# and determine if it is likely of malicious intent, or if it is safe to interact with.
# The email is attached below. \n {}""".format(persona, values, vectors, email)
