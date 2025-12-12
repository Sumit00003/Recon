import os
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate

# Load model
llm = ChatGroq(
    groq_api_key=os.getenv("GROQ_API_KEY"),
    model="llama-3.1-8b-instant"   # your working model
)

# =============================
#  PROMPT 1 — HTTPX ANALYSIS
# =============================

subdomain_prompt = ChatPromptTemplate.from_template("""
You are a senior penetration tester.

Below is the httpx output. Each line contains:
- Subdomain
- Status code
- (Optional) server name

Your tasks:
1. Suggest exact tests based on server name + status code.
2. Highlight any server with known CVEs.
3. Cluster subdomains by business function (auth, api, cdn, staging, admin, dev).
4. Identify security-sensitive hosts (admin, staging, dev, test, beta).
5. Suggest ideas & test cases or nuclei templates for each cluster (auth brute force, misconfigurations, broken access control, SSRF, CORS issues, IDOR, etc.)

Data:
{httpx_data}
""")

subdomain_chain = subdomain_prompt | llm


# =============================
#  PROMPT 2 — URL / PARAMETER ANALYSIS
# =============================

parameter_prompt = ChatPromptTemplate.from_template("""
You are a senior bug bounty hunter.

Below are unique URLs extracted from Katana.

Your tasks:
1. Identify potential vulnerabilities based on Parameter names
2. Suggest EXACT attacks (payloads included).
3. Point out interesting URLs and why.

Data:
{url_data}
""")

parameter_chain = parameter_prompt | llm

# =============================
#  PROMPT 3 — Waybackurls
# =============================
'''
waybackurl_prompt = ChatPromptTemplate.from_template("""
You are a senior bug bounty hunter.

Below is waybackurls tool output.

Your tasks:
1. Identify interesting historical endpoints(e.g., /backup, /admin or .bak, .old file)
2. Mark which endpoints are likely still exploitable
3. Suggest how to test each interesting endpoint.

Data:
{wayback_data}
""")

waybackurl_chain = waybackurl_prompt | llm
'''
# =============================
#  PROMPT 3 — NEXT STEPS
# =============================

next_steps_prompt = ChatPromptTemplate.from_template("""
Using both analyses (subdomains + URLs), provide:

1. What to test next based on what I found in the following file (e.g., Brute forcing urls with 404 to find any sensitive file, or trying to bypass 403 url to access the endpoints etc)
2. Which techniques & Github tools to use next

HTTPX Analysis:
{httpx_analysis}

URL Analysis:
{url_analysis}
""")

next_steps_chain = next_steps_prompt | llm


# =============================
#   PROCESS FILES
# =============================

httpx_file = "httpx.txt"
urls_file = "params_urls.txt"
#wayback = "waybackurls.txt"

httpx_data = open(httpx_file).read().strip() if os.path.exists(httpx_file) else ""
url_data = open(urls_file).read().strip() if os.path.exists(urls_file) else ""
#wayback_data = open(wayback).read().strip() if os.path.exists(wayback) else ""

# Run HTTPX analysis
if httpx_data:
    httpx_result = subdomain_chain.invoke({"httpx_data": httpx_data}).content
else:
    httpx_result = "No httpx data found."

# Run URL analysis
if url_data:
    url_result = parameter_chain.invoke({"url_data": url_data}).content
else:
    url_result = "No params_urls data found."
    
 
'''# Run Wayback analysis
if wayback_data:
    wayback_result = waybackurl_chain.invoke({"wayback_data": wayback_data}).content
else:
    wayback_result = "No Waybackurl data found."
'''

# Run Next Steps analysis
# if statement dalna idhar
next_steps_result = next_steps_chain.invoke({
    "httpx_analysis": httpx_result,
    "url_analysis": url_result,
}).content


# =============================
#   SAVE TO MARKDOWN FILE
# =============================

md_content = f"""
# Recon Analysis Report

---

## 1. HTTPX Output Analysis
{httpx_result}

---

## 2. URL Parameter / Endpoint Analysis
{url_result}

---

## 3. Recommended Next Steps (What To Do Next)
{next_steps_result}

"""

output_file = "recon_report.md"

with open(output_file, "w", encoding="utf-8") as f:
    f.write(md_content)

print(f"\nMarkdown file created: {output_file}")
