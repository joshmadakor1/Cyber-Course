import openai
import time
import csv

ChatGPT_API_KEY = "xxxxxxxxxxxxxxxxxxxx" # https://platform.openai.com/api-keys)
GPT_MODEL = "gpt-4-0125-preview" # API Models: https://platform.openai.com/docs/models/continuous-model-upgrades

def get_csv_contents(file_path):
    
    try:
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            data = [row for row in reader]
        return data
    except Exception as e:
       print(f"Error:\n\n{e}\n\n——————————")

def get_tsv_contents(input_file_path):
    all_rows = []
    with open(input_file_path, mode='r', encoding='utf-8') as infile:
        reader = csv.reader(infile, delimiter='\t')
        for row in reader:
            all_rows.append('\t'.join(row))
    return '\n'.join(all_rows)
            
def get_text_contents(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        contents = file.read()
    return contents

def create_prompt(job_description, nice_framework):
    return f'''
Based on the [NICE Cybersecurity Framework] and definition of
Job roles defined below, what is the most appropriate
job role listed in the spreadsheet for the job description below?
Please only choose roles which appear in the "role" column of the
[NICE Cybersecurity Framework]. 
Analyze the included content accurately to identify the most
suitable role for the job description provided. Do not [Output]
in any other way than what I describe below (after the Job Description section).
—
[Job Description]:
{job_description}
—
[NICE Cybersecurity Framework]:
{nice_framework}
—
[Output]:
{{
"role":"((the role from the [NICE Cybersecurity Framework] that closest matches the [Job Description]",
"explanation":"((justification for your selection))"
}}
—

    '''

def ask_chatgpt(key, model, prompt):
   # Plug the API key into the openai object
    openai.api_key = key

    print("Asking ChatGPT.")

    while True:
        try:
            response = openai.ChatCompletion.create(
                model=model,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            response = response.choices[0].message.content
            return response

        except Exception as e:
            print(f"An error occurred: {e}")
            print("Retrying...")
            time.sleep(1)  # Pause for a second before retrying

def clean_up_response(response):
    cleaned_response = response.replace('\n','')
    return cleaned_response

def dump_contents_to_text_file(new_file_name, contents):
    try:
        with open(new_file_name, 'w') as file:
            file.write(contents)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

# ----- SCRIPT RUNS HERE ----- #
print("—")
job_description = get_text_contents("internet-job-description.txt")
NICE_framework = get_tsv_contents("nice-roles.tsv")
prompt = create_prompt(job_description, NICE_framework)
response = ask_chatgpt(ChatGPT_API_KEY, GPT_MODEL, prompt)
cleaned_response = clean_up_response(response)
dump_contents_to_text_file("actual-job-description.json", cleaned_response)
dump_contents_to_text_file("prompt.txt", prompt)
print('fin.')
print("—")
