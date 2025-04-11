#!/usr/bin/env python3

import base64
import os
from google import genai
from google.genai import types


#Gathering User Insight
print("""Hello user, we will need to gather some insight into your malicious situation. 
      \n Please answer the following questions with as mcuh detail as possible.
      Type not sure if there is no clear answer. """)

persona = input("Who are you? (Ex: Student, Job Position, etc.): ")
value = input("What potentially valuable information do you hold? (Passwords, Access, Corporate Secrets, etc.): ")
vectors = input("How could an attacker have found you? (Public Relations, Compromised Email, Website Sign-Ups): )")

#Virus Total Assesment
email = input("Now enter the suspected email, including any webpage links attached: ")

#Parse input for attachments and plug them into virustotal, add score into prompt

#Creating prompt for comprehensive analysis
prompt = """nothing so far..."""



#Defines scope of gemini and inputs prompt
def generate():
    client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY"),
    )

    model = "gemini-2.0-flash"
    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part.from_text(text=prompt),
            ],
        ),
    ]
    generate_content_config = types.GenerateContentConfig(
        response_mime_type="text/plain",
    )

    for chunk in client.models.generate_content_stream(
        model=model,
        contents=contents,
        config=generate_content_config,
    ):
        print(chunk.text, end="")

#Executes text generation
if __name__ == "__main__":
    generate()
