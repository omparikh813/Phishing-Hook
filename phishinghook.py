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

#Retrieves payload of message and removes encoding from embedded text to not confuse AI
forwarded_msg = msg.get_payload()[0].get_payload()
forwarded_msg = re.sub(r"=\w{1,2}", "", forwarded_msg)

#Parse email for attachments and suspected threat actor
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
prompt = """
    Using the email "{}", analyze the name and domain to determine who they are (ex. personal, corporate account, etc.). 
    This is the receiver of the email. Then determine their potentially valuable assets (ex. passwords, capital, corporate secrets or access, etc.), 
    and what vectors a possible attacker could use to reach them (ex. compromised email, email list, etc.). 
    This email address had an email sent to them which they suspect of being a phishing email. The suspected email is attached to the end of this prompt, with the sender being "{}".
    Keep in mind that the sender could be an automated account of a legit website. Use the analsis of the reciever (persona, assets, attack vectors), the following email contents, 
    and a list of VirusTotal reviews of the attached links to determine the likelihood of the email being a phishing attempt. 
    The report should be in one concise, 5 sentence pargraph, and include a score from 0 to 100 with 0 being no likely phishing attempt and 100 being a definite threat.

    Email Contents: "{}"
    VirusTotal Analysis: "{}"

    """.format(email, from_email, forwarded_msg, str(reviews))

# Generates report
response = model.generate_content(prompt)
print(response.text)

quit()
